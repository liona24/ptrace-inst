# ptrace-inst

A very basic dynamic instrumentation library built on top of ptrace

## Building

```bash
$ mkdir build
$ cd build
$ cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
$ ninja
```

## Running the examples

```bash
$ python3 -m examples.helloworld.main
```
