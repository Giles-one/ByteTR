#!/usr/bin/env python
# -------------------------------------------------------------------------------
# scripts/dwarfdump.py
#
# A clone of 'llvm-dwarfdump' in Python, based on the pyelftools library
# Roughly corresponding to v15
#
# Sources under https://github.com/llvm/llvm-project/tree/main/llvm/tools/llvm-dwarfdump
#
# Utterly incompatible with 64-bit DWARF or DWARFv2 targeting a 64-bit machine.
# Also incompatible with machines that have a selector/segment in the address.
#
# Eli Bendersky (eliben@gmail.com)
# This code is in the public domain
# -------------------------------------------------------------------------------
import argparse
import os, sys
import traceback
import random

from tqdm import tqdm

import glob
import json
import multiprocessing
from collections import namedtuple

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')

from elftools import __version__
from elftools.common.exceptions import DWARFError, ELFError
from elftools.common.utils import bytes2str
from elftools.elf.elffile import ELFFile
from elftools.dwarf.locationlists import LocationParser, LocationEntry, LocationExpr, LocationViewPair, \
    BaseAddressEntry as LocBaseAddressEntry
from elftools.dwarf.ranges import RangeEntry  # ranges.BaseAddressEntry collides with the one above
import elftools.dwarf.ranges
from elftools.dwarf.enums import *
from elftools.dwarf.dwarf_expr import DWARFExprParser, DWARFExprOp
from elftools.dwarf.datatype_cpp import DIE_name, describe_cpp_datatype, _custom_describe_datatype, TypeDesc
from elftools.dwarf.descriptions import describe_reg_name

# ------------------------------
import logging

logging.basicConfig(
    level=logging.ERROR,
    format='[%(levelname)s]->[%(asctime)s]-> %(message)s'
)
logger = logging.getLogger(__name__)


# ------------------------------

def _get_cu_base(cu):
    top_die = cu.get_top_DIE()
    attr = top_die.attributes
    if 'DW_AT_low_pc' in attr:
        return attr['DW_AT_low_pc'].value
    elif 'DW_AT_entry_pc' in attr:
        return attr['DW_AT_entry_pc'].value
    else:
        raise ValueError("Can't find the base IP (low_pc) for a CU")


def _addr_str_length(die):
    return die.cu.header.address_size * 2


def _DIE_name(die):
    if 'DW_AT_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_name'].value)
    elif 'DW_AT_linkage_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_linkage_name'].value)
    else:
        raise DWARFError()


def _DIE_linkage_name(die):
    if 'DW_AT_linkage_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_linkage_name'].value)
    elif 'DW_AT_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_name'].value)
    else:
        raise DWARFError()


def _safe_DIE_name(die, default=None):
    if 'DW_AT_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_name'].value)
    elif 'DW_AT_linkage_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_linkage_name'].value)
    else:
        return default


def _safe_DIE_linkage_name(die, default=None):
    if 'DW_AT_linkage_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_linkage_name'].value)
    elif 'DW_AT_name' in die.attributes:
        return bytes2str(die.attributes['DW_AT_name'].value)
    else:
        return default


def _desc_ref(attr, die, extra=''):
    if extra:
        extra = " \"%s\"" % extra
    # TODO: leading zeros on the addend to CU - sometimes present, sometimes not.
    # Check by the LLVM sources.
    return "cu + 0x%04x => {0x%08x}%s" % (
        attr.raw_value,
        die.cu.cu_offset + attr.raw_value,
        extra)


def _desc_data(attr, die):
    """ Hex with length driven by form
    """
    len = int(attr.form[12:]) * 2
    return "0x%0*x" % (len, attr.value,)


def _desc_strx(attr, die):
    return "indexed (%08x) string = \"%s\"" % (attr.raw_value, bytes2str(attr.value).replace("\\", "\\\\"))


CUSTOM_FORM_DESCRIPTIONS = dict(
    DW_FORM_data1=lambda attr, die: '%d' % attr.value,
    DW_FORM_data2=lambda attr, die: '%d' % attr.value,
    DW_FORM_data4=lambda attr, die: '%d' % attr.value,
    DW_FORM_data8=lambda attr, die: '%d' % attr.value,

    DW_FORM_addr=lambda attr, die: '%d' % attr.value,
    DW_FORM_addrx=lambda attr, die: '%d' % attr.value,

    DW_FORM_strp=lambda attr, die: "%s" % (bytes2str(attr.value).replace("\\", "\\\\")),
    DW_FORM_line_strp=lambda attr, die: "%s" % (bytes2str(attr.value).replace("\\", "\\\\"))
)

FORM_DESCRIPTIONS = dict(
    DW_FORM_string=lambda attr, die: "\"%s\"" % (bytes2str(attr.value).replace("\\", "\\\\"),),
    DW_FORM_strp=lambda attr, die: " .debug_str[0x%08x] = \"%s\"" % (
    attr.raw_value, bytes2str(attr.value).replace("\\", "\\\\")),
    DW_FORM_strx1=_desc_strx,
    DW_FORM_strx2=_desc_strx,
    DW_FORM_strx3=_desc_strx,
    DW_FORM_strx4=_desc_strx,
    DW_FORM_line_strp=lambda attr, die: ".debug_line_str[0x%08x] = \"%s\"" % (
    attr.raw_value, bytes2str(attr.value).replace("\\", "\\\\")),
    DW_FORM_flag_present=lambda attr, die: "true",
    DW_FORM_flag=lambda attr, die: "0x%02x" % int(attr.value),
    DW_FORM_addr=lambda attr, die: "0x%0*x" % (_addr_str_length(die), attr.value),
    DW_FORM_addrx=lambda attr, die: "indexed (%08x) address = 0x%0*x" % (
    attr.raw_value, _addr_str_length(die), attr.value),
    DW_FORM_data1=_desc_data,
    DW_FORM_data2=_desc_data,
    DW_FORM_data4=_desc_data,
    DW_FORM_data8=_desc_data,
    DW_FORM_block1=lambda attr, die: "<0x%02x> %s " % (len(attr.value), " ".join("%02x" % b for b in attr.value)),
    DW_FORM_block2=lambda attr, die: "<0x%04x> %s " % (len(attr.value), " ".join("%02x" % b for b in attr.value)),
    DW_FORM_block4=lambda attr, die: "<0x%08x> %s " % (len(attr.value), " ".join("%02x" % b for b in attr.value)),
    DW_FORM_ref=_desc_ref,
    DW_FORM_ref1=_desc_ref, DW_FORM_ref2=_desc_ref,
    DW_FORM_ref4=_desc_ref, DW_FORM_ref8=_desc_ref,
    DW_FORM_sec_offset=lambda attr, die: "0x%08x" % (attr.value,),
    DW_FORM_exprloc=lambda attr, die: _desc_expression(attr.value, die)
)


def _desc_enum(attr, enum):
    """For attributes like DW_AT_language, physically
    int, logically an enum
    """
    return next((k for (k, v) in enum.items() if v == attr.value), str(attr.value))


def _cu_comp_dir(cu):
    return bytes2str(cu.get_top_DIE().attributes['DW_AT_comp_dir'].value)


def _desc_decl_file(attr, die):
    # Filename/dirname arrays are 0 based in DWARFv5
    cu = die.cu
    if not hasattr(cu, "_lineprogram"):
        cu._lineprogram = die.dwarfinfo.line_program_for_CU(cu)
    ver5 = cu._lineprogram.header.version >= 5
    file_index = attr.value if ver5 else attr.value - 1
    if cu._lineprogram and file_index >= 0 and file_index < len(cu._lineprogram.header.file_entry):
        file_entry = cu._lineprogram.header.file_entry[file_index]
        dir_index = file_entry.dir_index if ver5 else file_entry.dir_index - 1
        includes = cu._lineprogram.header.include_directory
        if dir_index >= 0:
            dir = bytes2str(includes[dir_index])
            if dir.startswith('.'):
                dir = os.path.join(_cu_comp_dir(cu), dir)
        else:
            dir = _cu_comp_dir(cu)
        file_name = bytes2str(file_entry.name)
    else:
        raise DWARFError("Invalid source filename entry index in a decl_file attribute")
    return "\"%s\"" % (os.path.join(dir, file_name),)


def _desc_ranges(attr, die):
    di = die.cu.dwarfinfo
    if not hasattr(di, '_rnglists'):
        di._rangelists = di.range_lists()
    rangelist = di._rangelists.get_range_list_at_offset(attr.value, die.cu)
    base_ip = _get_cu_base(die.cu)
    lines = []
    addr_str_len = die.cu.header.address_size * 2
    for entry in rangelist:
        if isinstance(entry, RangeEntry):
            lines.append("                 [0x%0*x, 0x%0*x)" % (
                addr_str_len,
                (0 if entry.is_absolute else base_ip) + entry.begin_offset,
                addr_str_len,
                (0 if entry.is_absolute else base_ip) + entry.end_offset))
        elif isinstance(entry, elftools.dwarf.ranges.BaseAddressEntry):
            base_ip = entry.base_address
        else:
            raise NotImplementedError("Unknown object in a range list")
    prefix = "indexed (0x%x) rangelist = " % attr.raw_value if attr.form == 'DW_FORM_rnglistx' else ''
    return ("%s0x%08x\n" % (prefix, attr.value)) + "\n".join(lines)


def _desc_locations(attr, die):
    cu = die.cu
    di = cu.dwarfinfo
    if not hasattr(di, '_loclists'):
        di._loclists = di.location_lists()
    if not hasattr(di, '_locparser'):
        di._locparser = LocationParser(di._loclists)
    loclist = di._locparser.parse_from_attribute(attr, cu.header.version, die)
    if isinstance(loclist, LocationExpr):
        parsedLoc, desc = _custom_desc_expression(loclist.loc_expr, die)
        return [LocationToSave(lowPC=-1, highPC=-1, desc=desc, dwarfExpr=parsedLoc)._asdict(), ]
    else:
        base_ip = _get_cu_base(cu)
        lines = []
        for entry in loclist:
            if isinstance(entry, LocationEntry):
                lowPC = (0 if entry.is_absolute else base_ip) + entry.begin_offset
                highPC = (0 if entry.is_absolute else base_ip) + entry.end_offset
                parsedLoc, desc = _custom_desc_expression(entry.loc_expr, die)
                locaTosave = LocationToSave(lowPC=lowPC, highPC=highPC, desc=desc, dwarfExpr=parsedLoc)
                lines.append(locaTosave._asdict())
            elif isinstance(entry, LocBaseAddressEntry):
                base_ip = entry.base_address
            else:
                raise NotImplementedError("Unknown object in a location list")
        return lines


# By default, numeric arguments are spelled in hex with a leading 0x
def _desc_operationarg(s, cu):
    if isinstance(s, str):
        return s
    elif isinstance(s, int):
        return hex(s)
    elif isinstance(s, list):  # Could be a blob (list of ints), could be a subexpression
        if len(s) > 0 and isinstance(s[0], DWARFExprOp):  # Subexpression
            return '(' + '; '.join(_desc_operation(op.op, op.op_name, op.args, cu) for op in s) + ')'
        else:
            return " ".join((hex(len(s)),) + tuple("0x%02x" % b for b in s))


def _arch(cu):
    return cu.dwarfinfo.config.machine_arch


def _desc_reg(reg_no, cu):
    return describe_reg_name(reg_no, _arch(cu), True).upper()


def _desc_operation(op, op_name, args, cu):
    # Not sure about regx(regno) and bregx(regno, offset)
    if 0x50 <= op <= 0x6f:  # reg0...reg31 - decode reg name
        return op_name + " " + _desc_reg(op - 0x50, cu)
    elif 0x70 <= op <= 0x8f:  # breg0...breg31(offset) - also decode reg name
        return '%s %s%+d' % (
            op_name,
            _desc_reg(op - 0x70, cu),
            args[0])
    elif op_name in (
    'DW_OP_fbreg', 'DW_OP_bra', 'DW_OP_skip', 'DW_OP_consts',):  # Argument is decimal with a leading sign
        return op_name + ' ' + "%+d" % (args[0])
    elif op_name in ('DW_OP_const1s', 'DW_OP_const2s'):  # Argument is decimal without a leading sign
        return op_name + ' ' + "%d" % (args[0])
    elif op_name in ('DW_OP_entry_value', 'DW_OP_GNU_entry_value'):  # No space between opcode and args
        return op_name + _desc_operationarg(args[0], cu)
    elif op_name == 'DW_OP_regval_type':  # Arg is a DIE pointer
        return "%s %s (0x%08x -> 0x%08x) \"%s\"" % (
            op_name,
            _desc_reg(args[0], cu),
            args[1],
            args[1] + cu.cu_offset,
            _DIE_name(cu._get_cached_DIE(args[1] + cu.cu_offset)))
    elif op_name == 'DW_OP_convert':  # Arg is a DIE pointer
        return "%s (0x%08x -> 0x%08x) \"%s\"" % (
            op_name,
            args[0],
            args[0] + cu.cu_offset,
            _DIE_name(cu._get_cached_DIE(args[0] + cu.cu_offset)))
    elif args:
        return op_name + ' ' + ', '.join(_desc_operationarg(s, cu) for s in args)
    else:
        return op_name


# TODO: remove this once dwarfdump catches up
UNSUPPORTED_OPS = (
    'DW_OP_implicit_pointer',
    'DW_OP_deref_type',
    'DW_OP_GNU_parameter_ref',
    'DW_OP_GNU_deref_type',
    'DW_OP_GNU_implicit_pointer',
    'DW_OP_GNU_convert',
    'DW_OP_GNU_regval_type')


def _desc_expression(expr, die):
    cu = die.cu
    if not hasattr(cu, '_exprparser'):
        cu._exprparser = DWARFExprParser(cu.structs)

    parsed = cu._exprparser.parse_expr(expr)
    # TODO: remove this once dwarfdump catches up
    first_unsupported = next((i for (i, op) in enumerate(parsed) if op.op_name in UNSUPPORTED_OPS), None)
    if first_unsupported is None:
        lines = [_desc_operation(op.op, op.op_name, op.args, cu) for op in parsed]
    else:
        lines = [_desc_operation(op.op, op.op_name, op.args, cu) for op in parsed[0:first_unsupported]]
        start_of_unparsed = parsed[first_unsupported].offset
        lines.append("<decoding error> " + " ".join("%02x" % b for b in expr[start_of_unparsed:]))
    return ", ".join(lines)


def _custom_desc_expression(expr, die):
    cu = die.cu
    if not hasattr(cu, '_exprparser'):
        cu._exprparser = DWARFExprParser(cu.structs)

    parsed = cu._exprparser.parse_expr(expr)
    lines = [_desc_operation(op.op, op.op_name, op.args, cu) for op in parsed]
    parsed = list([exprop._asdict() for exprop in parsed])
    lines = ", ".join(lines)
    return parsed, lines


def custom_desc_datatype(attr, die):
    # desc = _custom_describe_datatype(die)
    # return desc
    return describe_cpp_datatype(die)

def custom_desc_datatype_with_type_chain(attr, var_die):
    t = TypeDesc()

    if not 'DW_AT_type' in var_die.attributes:
        t.tag = ''
        return t

    type_die = var_die.get_DIE_from_attribute('DW_AT_type')

    typechain = []
    type_die_iter = type_die
    while True:
        typetag = type_die_iter.tag
        type_name = bytes2str(type_die_iter.attributes['DW_AT_name'].value) \
            if 'DW_AT_name' in type_die_iter.attributes \
            else ''

        type_size = type_die_iter.attributes['DW_AT_byte_size'].value \
            if 'DW_AT_byte_size' in type_die_iter.attributes \
            else -1

        if 'DW_AT_encoding' in type_die_iter.attributes:
            attr = type_die_iter.attributes['DW_AT_encoding']
            type_encoding = next((k for (k, v) in ENUM_DW_ATE.items() if v == attr.value), str(attr.value))
        else:
            type_encoding = ''

        typechain.append({
            'typetag': typetag,
            'typename': type_name,
            'typesize': type_size,
            'typencoding': type_encoding[7:],
        })

        if not type_die_iter.attributes.get('DW_AT_type'):
            break

        type_die_iter = type_die_iter.get_DIE_from_attribute('DW_AT_type')

    return typechain

def _desc_datatype(attr, die):
    """Oy vey
    """
    return _desc_ref(attr, die, describe_cpp_datatype(die))


def _get_origin_name(die):
    func_die = die.get_DIE_from_attribute('DW_AT_abstract_origin')
    name = _safe_DIE_linkage_name(func_die, '')
    if not name:
        if 'DW_AT_specification' in func_die.attributes:
            name = _DIE_linkage_name(func_die.get_DIE_from_attribute('DW_AT_specification'))
        elif 'DW_AT_abstract_origin' in func_die.attributes:
            return _get_origin_name(func_die)
    return name


def _desc_origin(attr, die):
    return _desc_ref(attr, die, _get_origin_name(die))


def _desc_spec(attr, die):
    return _desc_ref(attr, die,
                     _DIE_linkage_name(die.get_DIE_from_attribute('DW_AT_specification')))


def _desc_value(attr, die):
    return str(attr.value)


CUSTOM_ATTR_DESCRIPTIONS = dict(
    DW_AT_type=custom_desc_datatype,
)

ATTR_DESCRIPTIONS = dict(
    DW_AT_language=lambda attr, die: _desc_enum(attr, ENUM_DW_LANG),
    DW_AT_encoding=lambda attr, die: _desc_enum(attr, ENUM_DW_ATE),
    DW_AT_accessibility=lambda attr, die: _desc_enum(attr, ENUM_DW_ACCESS),
    DW_AT_inline=lambda attr, die: _desc_enum(attr, ENUM_DW_INL),
    DW_AT_calling_convention=lambda attr, die: _desc_enum(attr, ENUM_DW_CC),
    DW_AT_decl_file=_desc_decl_file,
    DW_AT_decl_line=_desc_value,
    DW_AT_ranges=_desc_ranges,
    DW_AT_location=_desc_locations,
    DW_AT_data_member_location=lambda attr, die: _desc_data(attr, die) if attr.form.startswith(
        'DW_FORM_data') else _desc_locations(attr, die),
    DW_AT_frame_base=_desc_locations,
    DW_AT_type=_desc_datatype,
    DW_AT_call_line=_desc_value,
    DW_AT_call_file=_desc_decl_file,
    DW_AT_abstract_origin=_desc_origin,
    DW_AT_specification=_desc_spec,
    DW_AT_call_site_value=lambda attr, die: _desc_expression(attr.value, die) if attr.form.startswith(
        'DW_FORM_block') else _desc_locations(attr, die),
    DW_AT_GNU_call_site_value=lambda attr, die: _desc_expression(attr.value, die) if attr.form.startswith(
        'DW_FORM_block') else _desc_locations(attr, die),
)

LocationToSave = namedtuple('LocationToSave', ('lowPC', 'highPC', 'desc', 'dwarfExpr'))


class ReadElf(object):
    """ dump_xxx is used to dump the respective section.
    Mimics the output of dwarfdump with --verbose
    """

    def __init__(self, filename, file, output):
        """ file:
                stream object with the ELF file to read

            output:
                output stream to write to
        """
        self.elffile = ELFFile(file)
        self.output = output
        self._dwarfinfo = self.elffile.get_dwarf_info()
        arches = {"EM_386": "i386", "EM_X86_64": "x86-64", "EM_ARM": "littlearm", "EM_AARCH64": "littleaarch64",
                  "EM_LOONGARCH": "loongarch", "EM_RISCV": "littleriscv", "EM_MIPS": "mips"}
        arch = arches[self.elffile['e_machine']]
        bits = self.elffile.elfclass
        self._emitline("%s:	file format elf%d-%s" % (filename, bits, arch))

    def _emit(self, s=''):
        """ Emit an object to output
        """
        self.output.write(str(s))

    def _emitline(self, s=''):
        """ Emit an object to output, followed by a newline
        """
        self.output.write(str(s).rstrip() + '\n')

    def dump_info(self):
        # TODO: DWARF64 will cause discrepancies in hex offset sizes
        self._emitline(".debug_info contents:")
        for cu in self._dwarfinfo.iter_CUs():
            if cu.header.version >= 5:
                unit_type_str = " unit_type = %s," % cu.header.unit_type
            else:
                unit_type_str = ''

            self._emitline(
                "0x%08x: Compile Unit: length = 0x%08x, format = DWARF%d, version = 0x%04x,%s abbr_offset = 0x%04x, addr_size = 0x%02x (next unit at 0x%08x)" % (
                    cu.cu_offset,
                    cu.header.unit_length,
                    cu.structs.dwarf_format,
                    cu.header.version,
                    unit_type_str,
                    cu.header.debug_abbrev_offset,
                    cu.header.address_size,
                    cu.cu_offset + (4 if cu.structs.dwarf_format == 32 else 12) + cu.header.unit_length))
            self._emitline()
            parent = cu.get_top_DIE()
            for die in cu.iter_DIEs():
                # if fetched die is the child of ** parent **; goto next level
                if die.get_parent() == parent:
                    parent = die
                if not die.is_null():
                    self._emitline("0x%08x: %s [%d] %s %s" % (
                        die.offset,
                        die.tag,
                        die.abbrev_code,
                        '*' if die.has_children else '',
                        '(0x%08x)' % die.get_parent().offset if die.get_parent() is not None else ''))
                    for attr_name in die.attributes:
                        attr = die.attributes[attr_name]
                        self._emitline("              %s [%s]	(%s)" % (
                            attr_name if isinstance(attr_name, str) else "DW_AT_unknown_%x" % (attr_name,),
                            attr.form,
                            self.describe_attr_value(die, attr)))
                # when fetched die is null, this level is ok; back to upper level
                else:
                    self._emitline("0x%08x: NULL" % (die.offset,))
                    parent = die.get_parent()
                self._emitline()

    # =========================================
    def check_subprogram_not_analyzable(self, die: elftools.dwarf.die.DIE):
        if len(die.attributes) == 0:
            return True
        if not die.attributes.get('DW_AT_name'):
            return True

        return False

    def subprogram_die_dynamic_linked(self, die: elftools.dwarf.die.DIE):
        subprogram_die_name = die.attributes.get('DW_AT_name')

        subprogram_die_frame_base = die.attributes.get('DW_AT_frame_base')
        if subprogram_die_frame_base:
            return False

        subprogram_die_low_pc = die.attributes.get('DW_AT_low_pc')
        if subprogram_die_low_pc:
            return False

        logger.info(
            '%s is dynamic_linked' % (
                self.custom_describe_attr_value(
                    die,
                    subprogram_die_name
                )
            )
        )
        return True

    def custom_describe_attr_value(self, die, attr):
        """This describes the attribute value in the way that's compatible
        with llvm_dwarfdump. Somewhat duplicates the work of describe_attr_value() in descriptions
        """
        if attr.name in CUSTOM_ATTR_DESCRIPTIONS:
            return CUSTOM_ATTR_DESCRIPTIONS[attr.name](attr, die)
        if attr.name in ATTR_DESCRIPTIONS:
            return ATTR_DESCRIPTIONS[attr.name](attr, die)
        elif attr.form in CUSTOM_FORM_DESCRIPTIONS:
            return CUSTOM_FORM_DESCRIPTIONS[attr.form](attr, die)
        elif attr.form in FORM_DESCRIPTIONS:
            return FORM_DESCRIPTIONS[attr.form](attr, die)
        else:
            return str(attr.value)

    def strip_str(self, string):
        string = string.replace('"', '')
        return string

    def get_local_variable_type(self, die: elftools.dwarf.die.DIE):
        variable_attrs = dict()
        for attr_name, attr in die.attributes.items():
            attr_name = attr_name if isinstance(attr_name, str) else "DW_AT_unknown_%x" % (attr_name)
            if attr_name == 'DW_AT_type':
                attr_desc = custom_desc_datatype(attr, die)
                variable_attrs[attr_name] = attr_desc

                attr_typechain_desc = custom_desc_datatype_with_type_chain(attr, die)
                variable_attrs['DW_AT_type_chain'] = attr_typechain_desc

            if attr_name == 'DW_AT_name':
                attr_desc = self.custom_describe_attr_value(die, attr)
                variable_attrs[attr_name] = attr_desc

        return variable_attrs

    def get_formal_parameter_type(self, die: elftools.dwarf.die.DIE):
        # parameter_attrs = {
        #     attr_name
        #     if isinstance(attr_name, str)
        #     else "DW_AT_unknown_%x" % (attr_name,)
        #     : self.strip_str(self.custom_describe_attr_value(die, attr))
        #     for attr_name, attr in die.attributes.items()
        # }
        # return parameter_attrs

        variable_attrs = dict()
        for attr_name, attr in die.attributes.items():
            attr_name = attr_name if isinstance(attr_name, str) else "DW_AT_unknown_%x" % (attr_name)
            if attr_name == 'DW_AT_type':
                attr_desc = custom_desc_datatype(attr, die)
                variable_attrs[attr_name] = attr_desc

                attr_typechain_desc = custom_desc_datatype_with_type_chain(attr, die)
                variable_attrs['DW_AT_type_chain'] = attr_typechain_desc

            if attr_name == 'DW_AT_name':
                attr_desc = self.custom_describe_attr_value(die, attr)
                variable_attrs[attr_name] = attr_desc

        return variable_attrs

    def get_external_function_call_type(self, die: elftools.dwarf.die.DIE):
        pass

    def get_inlined_subroutine_info(self, die: elftools.dwarf.die.DIE):
        pass

    def handle_lexical_block(self, die: elftools.dwarf.die.DIE):
        pass

    def handle_call_site_tag(self, die: elftools.dwarf.die.DIE):
        pass

    def hanle_subprogram_die(self, die: elftools.dwarf.die.DIE):
        if self.check_subprogram_not_analyzable(die):
            return None

        if self.subprogram_die_dynamic_linked(die):
            return None

        subprogram_attrs = dict()
        for attr_name, attr in die.attributes.items():
            attr_name = attr_name if isinstance(attr_name, str) else "DW_AT_unknown_%x" % (attr_name,)
            subprogram_attrs[attr_name] = self.custom_describe_attr_value(die, attr)

        function_name = subprogram_attrs['DW_AT_name']
        logger.info('hit function %s' % function_name)

        function_info = {
            'function_name': function_name,
            'variable': [],
            'parameter': [],
        }
        for _child in die.iter_children():
            child: elftools.dwarf.die.DIE = _child

            # handle function local variables; e.g. void main() {int a; int b}
            if child.tag == 'DW_TAG_variable':
                variable_attr = self.get_local_variable_type(child)
                function_info['variable'].append(variable_attr)

            # handle function parameters; e.g. void foo(int a, char* b) {...};
            elif child.tag == 'DW_TAG_formal_parameter':
                parameter_attrs = self.get_formal_parameter_type(child)
                function_info['parameter'].append(parameter_attrs)

            # handle call the external function; e.g. void main() { printf("Hello World\n");}
            elif child.tag == 'DW_TAG_subprogram':
                self.get_external_function_call_type(child)

            # handle lexical block; e.g. { int a = 10; if (a) { int b = 10;} }
            elif child.tag == 'DW_TAG_lexical_block':
                self.handle_lexical_block(child)

            # handle inlined_subroutine; e.g. int main{ printf("Hello World\n"); } when compiled with -O[1-s]
            # It commonly has it's child DW_TAG_call_site die
            elif child.tag == 'DW_TAG_inlined_subroutine':
                self.get_inlined_subroutine_info(child)

            # handle DW_TAG_call_site of direct call; e.g. int main() { foo(a); }. backtrace
            elif child.tag == 'DW_TAG_call_site':
                self.handle_call_site_tag(child)

            # enum action_type { nothing, compress, decompress };
            elif child.tag == 'DW_TAG_enumeration_type':
                # breakpoint()
                pass  # it doesnot matter.

            # same to call_site
            elif child.tag == 'DW_TAG_GNU_call_site':
                # breakpoint()
                pass

            # out: ....
            elif child.tag == 'DW_TAG_label':
                # breakpoint()
                pass  # it does not matter

            # strutc { ... }
            elif child.tag == 'DW_TAG_structure_type':
                # breakpoint()
                pass  # we will hanle this in future

            elif child.tag == 'DW_TAG_template_type_parameter':
                # breakpoint()
                pass

            elif child.tag == 'DW_TAG_typedef':
                # breakpoint()
                pass

                # valist
            elif child.tag == 'DW_TAG_unspecified_parameters':
                # breakpoint()
                pass  # We don't care fuck this

            else:
                logger.info('This Tag Not in considering -> %s' % child.tag)
                pass

        if len(function_info['variable']) + len(function_info['parameter']) == 0:
            return None

        return function_info

    def get_data_type_info(self, fp):
        if not self._dwarfinfo.has_debug_info:
            logger.error('This ELF has no debug_info.')
            return None

        collect_ELF_info = []
        for cu in self._dwarfinfo.iter_CUs():
            if cu.header.version > 5:
                logger.error("Current We don't support dwarf->5. Please compile with '-gdwarf-5' option. ")
                return None

            top_die = cu.get_top_DIE()
            language_attr = top_die.attributes.get('DW_AT_language')
            if language_attr:
                language = self.custom_describe_attr_value(top_die, language_attr)
            else:
                language = 'DW_LANG_SUCKS'

            if not language in ('DW_LANG_C89',
                                'DW_LANG_C',
                                'DW_LANG_C99',
                                'DW_LANG_C11',
                                'DW_LANG_C17',
                                'DW_LANG_C_plus_plus',
                                'DW_LANG_C_plus_plus_03',
                                'DW_LANG_C_plus_plus_11',
                                'DW_LANG_C_plus_plus_14',
                                'DW_LANG_C_plus_plus_17',
                                'DW_LANG_C_plus_plus_20',
                                'DW_LANG_C_plus_plus_23'
            ):
                continue

            for child in top_die.iter_children():
                if not child.tag == 'DW_TAG_subprogram':
                    continue
                result = self.hanle_subprogram_die(child)
                if not result:
                    continue
                fp.write(json.dumps(result) + '\n')
                fp.flush()

    def get_data_type_info_v0(self):
        self._emitline(".debug_info contents:")
        for cu in self._dwarfinfo.iter_CUs():
            if cu.header.version >= 5:
                unit_type_str = " unit_type = %s," % cu.header.unit_type
            else:
                unit_type_str = ''

            self._emitline(
                "0x%08x: Compile Unit: length = 0x%08x, format = DWARF%d, version = 0x%04x,%s abbr_offset = 0x%04x, addr_size = 0x%02x (next unit at 0x%08x)" % (
                    cu.cu_offset,
                    cu.header.unit_length,
                    cu.structs.dwarf_format,
                    cu.header.version,
                    unit_type_str,
                    cu.header.debug_abbrev_offset,
                    cu.header.address_size,
                    cu.cu_offset + (4 if cu.structs.dwarf_format == 32 else 12) + cu.header.unit_length))
            self._emitline()
            parent = cu.get_top_DIE()
            for die in cu.iter_DIEs():
                # if fetched die is the child of ** parent **; goto next level
                if die.get_parent() == parent:
                    parent = die
                if not die.is_null():
                    self._emitline("0x%08x: %s [%d] %s %s" % (
                        die.offset,
                        die.tag,
                        die.abbrev_code,
                        '*' if die.has_children else '',
                        '(0x%08x)' % die.get_parent().offset if die.get_parent() is not None else ''))
                    for attr_name in die.attributes:
                        if attr_name == 'DW_AT_ranges':
                            continue
                        attr = die.attributes[attr_name]
                        self._emitline(
                            "              %s [%s]	(%s)" % (
                                attr_name if isinstance(attr_name, str) else "DW_AT_unknown_%x" % (attr_name,),
                                attr.form,
                                self.describe_attr_value(die, attr)))
                    # handling one die to collect datainfo
                    if die.tag == 'DW_TAG_subprogram':
                        self.hanle_subprogram_die(die)
                # when fetched die is null, this level is ok; back to upper level
                else:
                    self._emitline("0x%08x: NULL" % (die.offset,))
                    parent = die.get_parent()
                self._emitline()

    # ============================================================================
    def describe_attr_value(self, die, attr):
        """This describes the attribute value in the way that's compatible
        with llvm_dwarfdump. Somewhat duplicates the work of describe_attr_value() in descriptions
        """
        if attr.name in ATTR_DESCRIPTIONS:
            return ATTR_DESCRIPTIONS[attr.name](attr, die)
        elif attr.form in FORM_DESCRIPTIONS:
            return FORM_DESCRIPTIONS[attr.form](attr, die)
        else:
            return str(attr.value)

    def dump_loc(self):
        pass

    def dump_loclists(self):
        pass

    def dump_ranges(self):
        pass

    def dump_v4_rangelist(self, rangelist, cu_map):
        cu = cu_map[rangelist[0].entry_offset]
        addr_str_len = cu.header.address_size * 2
        base_ip = _get_cu_base(cu)
        for entry in rangelist:
            if isinstance(entry, RangeEntry):
                self._emitline("[0x%0*x, 0x%0*x)" % (
                    addr_str_len,
                    (0 if entry.is_absolute else base_ip) + entry.begin_offset,
                    addr_str_len,
                    (0 if entry.is_absolute else base_ip) + entry.end_offset))
            elif isinstance(entry, elftools.dwarf.ranges.BaseAddressEntry):
                base_ip = entry.base_address
            else:
                raise NotImplementedError("Unknown object in a range list")

    def dump_rnglists(self):
        self._emitline(".debug_rnglists contents:")
        ranges_sec = self._dwarfinfo.range_lists()
        if ranges_sec.version < 5:
            return

        cu_map = {die.attributes['DW_AT_ranges'].value: cu  # Dict from range offset to home CU
                  for cu in self._dwarfinfo.iter_CUs()
                  for die in cu.iter_DIEs()
                  if 'DW_AT_ranges' in die.attributes}

        for cu in ranges_sec.iter_CUs():
            self._emitline(
                "0x%08x: range list header: length = 0x%08x, format = DWARF%d, version = 0x%04x, addr_size = 0x%02x, seg_size = 0x%02x, offset_entry_count = 0x%08x" % (
                    cu.cu_offset,
                    cu.unit_length,
                    64 if cu.is64 else 32,
                    cu.version,
                    cu.address_size,
                    cu.segment_selector_size,
                    cu.offset_count))
            self._emitline("ranges:")
            if cu.offset_count > 0:
                rangelists = [ranges_sec.get_range_list_at_offset_ex(offset) for offset in cu.offsets]
            else:
                rangelists = list(ranges_sec.iter_CU_range_lists_ex(cu))
            # We have to parse it completely before dumping, because dwarfdump aligns columns,
            # no way to do that without some lookahead
            max_type_len = max(len(entry.entry_type) for rangelist in rangelists for entry in rangelist)
            for rangelist in rangelists:
                self.dump_v5_rangelist(rangelist, cu_map, max_type_len)

    def dump_v5_rangelist(self, rangelist, cu_map, max_type_len):
        cu = cu_map[rangelist[0].entry_offset]
        addr_str_len = cu.header.address_size * 2
        base_ip = _get_cu_base(cu)
        for entry in rangelist:
            type = entry.entry_type
            self._emit("0x%08x: [%s]:  " % (entry.entry_offset, type.ljust(max_type_len)))
            if type == 'DW_RLE_base_address':
                base_ip = entry.address
                self._emitline("0x%0*x" % (addr_str_len, base_ip))
            elif type == 'DW_RLE_offset_pair':
                self._emitline("0x%0*x, 0x%0*x => [0x%0*x, 0x%0*x)" % (
                    addr_str_len, entry.start_offset,
                    addr_str_len, entry.end_offset,
                    addr_str_len, entry.start_offset + base_ip,
                    addr_str_len, entry.end_offset + base_ip))
            elif type == 'DW_RLE_start_length':
                self._emitline("0x%0*x, 0x%0*x => [0x%0*x, 0x%0*x)" % (
                    addr_str_len, entry.start_address,
                    addr_str_len, entry.length,
                    addr_str_len, entry.start_address,
                    addr_str_len, entry.start_address + entry.length))
            elif type == 'DW_RLE_start_end':
                self._emitline("0x%0*x, 0x%0*x => [0x%0*x, 0x%0*x)" % (
                    addr_str_len, entry.start_address,
                    addr_str_len, entry.end_address,
                    addr_str_len, entry.start_address,
                    addr_str_len, entry.end_address))
            else:
                raise NotImplementedError()
        last = rangelist[-1]
        self._emitline("0x%08x: [DW_RLE_end_of_list ]" % (last.entry_offset + last.entry_length,))


SCRIPT_DESCRIPTION = 'Display information about the contents of ELF format files'
VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__


def process_ELF(filepath, stream=None):
    if not os.path.isfile(filepath):
        print('Error: %s is not a file.' % (filepath))
    logger.info('handling %s' % (filepath))

    saveTo = filepath + '.ea.exp1.jsonl'
    with open(saveTo, 'w') as fp:
        with open(filepath, 'rb') as file:
            readelf = ReadElf(
                filepath,
                file,
                stream if stream else sys.stdout
            )
            result = readelf.get_data_type_info(fp)

def compatibility_init():
    # A compatibility hack on top of a compatibility hack :(
    del ENUM_DW_TAG["DW_TAG_template_type_param"]
    del ENUM_DW_TAG["DW_TAG_template_value_param"]
    ENUM_DW_TAG['DW_TAG_template_type_parameter'] = 0x2f
    ENUM_DW_TAG['DW_TAG_template_value_parameter'] = 0x30


def GNU():
    root_path = './test'
    ELF_file_list = []
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if not file.endswith('.elf'):
                continue
            if 'x86_64' not in file:
                continue
            filepath = os.path.join(root, file)
            ELF_file_list.append(filepath)
    logger.info('Collect ELF files %d' % (len(ELF_file_list)))

    random.shuffle(ELF_file_list)
    for elf_filepath in ELF_file_list:
        with open(os.devnull, 'w') as stream:
            process_ELF(elf_filepath, stream)


def TinyHTTP():
    ELF_file_list = []
    root_path = '../demo/Tinyhttpd/'
    for root, dirs, files in os.walk(root_path):
        for file in files:
            if not file.endswith('.elf'):
                continue
            filepath = os.path.join(root, file)
            ELF_file_list.append(filepath)
    logger.info('Collect ELF files %d' % (len(ELF_file_list)))

    random.shuffle(ELF_file_list)
    for elf_filepath in ELF_file_list:
        with open(os.devnull, 'w') as stream:
            process_ELF(elf_filepath, stream)


def worker(ELFPath):
    # with open('/tmp/b', 'w') as fp:
    try:
        if ELFPath is None:
            raise KeyError(f"'ELF' key not found in {ELFPath}")
        with open(os.devnull, 'w') as stream:
            process_ELF(ELFPath, stream)

    except Exception as e:
        return f"Error processing ELF: {str(e)}"


def speedup(ELFCollect):
    numCores = 40
    pool = multiprocessing.Pool(processes=numCores)

    list(tqdm(pool.imap_unordered(worker, ELFCollect), total=len(ELFCollect)))
    pool.close()
    pool.join()

def getFilesByDir(directory):
    filePaths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            filePaths.append(os.path.join(root, file))
    return filePaths

def getMetaInfoByELF(elfPath):
    try:
        with open(elfPath, 'rb') as f:
            elf = ELFFile(f)
            return {
                'Machine': elf.get_machine_arch(),
                'Entry': hex(elf['e_entry']),
                'Type': elf['e_type'],
                'Debug': elf.get_dwarf_info().has_debug_info
            }
    except Exception as e:
        # print(f"Error processing {elfPath}: {str(e)}")
        return None

def argParse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--dir',
        type=str,
        default='/archive/lgy/TYDA/demo/x86_64/O0/',
        help="Root Directory."
    )
    parser.add_argument(
        '--saveto',
        type=str,
        default='.',
        help="."
    )
    args = parser.parse_args()
    return args



def main(args):
    compatibility_init()

    worker("/data/lgy/Projects/dataTypeInference/project/experiment/empiricalAnalysis/exp1/types")
    
if __name__ == '__main__':
    args = argParse()
    main(args)

