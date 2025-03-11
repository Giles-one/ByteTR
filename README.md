### Overview

*ByteTR* is a framework designed for recovering variable types in binary code. It utilizes inter-procedural program analysis to construct variable semantic graphs and employs graph neural networks to restore variable types.

<p align="center">
  <img src="assets/overview.png" alt="Example Image" width="90%" />
</p>

### Project

#### 1. EmpiricalAnalysis

Conduct empirical analysis experiments on binary code using the following commands.

- Type Frequency
- Zipf's and Heaps' Laws
- Pattern of Storage

```
$ pushd EmpiricalAnalysis/<EXP>/
$ python step1.py
$ python step2.py
$ popd
```

The following experiments require IDA, which we have encapsulated in a Docker container (IDA 9.0).

- Number of Functions
- Number of Variables
- Locality of Reference

```
$ pushd EmpiricalAnalysis/<EXP>/
$ docker run \
    -it \
    -v <TYDA_DATASET>:/dataset/ \
    -v $(pwd)/idascript:/idascript \
    --rm \
    lgy/ida
# cd /idascript && python launcher.py
# exit
$ python step1.py
$ python step2.py
$ popd
```

#### 2. BinaryProcessing

First, configure `binary.config.json` and `public.config.json` in the `config` directory. Then, navigate to the `BinaryProcessing` folder and follow the steps to process the binary files. `<ARCH>` and `<OPT>` specify the architecture and optimization options, respectively.

```
$ pushd BinaryProcessing/
$ python step0.selectELF.py \
    --arch <ARCH> \
    --opt <OPT>
$ python step1.parseDwarfInfo.py \
    --arch <ARCH> \
    --opt <OPT>
$ python step2.parseCfiInfo.py \
    --arch <ARCH> \
    --opt <OPT>
```

#### 3. BytePA
This section will be open-sourced after the paper is published. Thank you for your understanding.

#### 4. ByteTP
This section will be open-sourced after the paper is published. Thank you for your understanding.
