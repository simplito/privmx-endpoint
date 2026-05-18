# Creating dataset
To create the dataset required for testing run:
```bash
./test_env/create_dataset/main.sh
```

To list advanced options in the dataset creation tool run:
```bash
./test_env/create_dataset/main.sh --help
```

The dataset is created by default in `test_env/create_dataset` with a name like `Dataset_YYYY-mm-dd_HH-MM`.

# Running tests
When you use conan, remember to use `conanrun.sh` or all tests will fail.

## Python setup
The runner manages a local virtual environment in `test/.venv` and installs dependencies from `test/requirements.txt`.

Initial setup only:
```bash
python3 e2e_runner.py --setup-python
```

On the first regular run, if Python dependencies are missing, `e2e_runner.py` will create `test/.venv`, install the required packages and restart itself automatically.

## Setup mongo docker
```bash
docker compose up -d
```

### Stream API requirements
Minimum one video device that is streaming data.

### Example setup

```bash
# Installing akvcam
git clone https://github.com/webcamoid/akvcam.git
cd akvcam/src/
make
sudo make dkms_install
sudo mkdir -p /etc/akvcam
sudo cat > /etc/akvcam/config.ini << EOF
[Cameras]
cameras/size = 2

cameras/1/type = output
cameras/1/mode = mmap, userptr, rw
cameras/1/description = Virtual Camera (output device)
cameras/1/formats = 1, 2
cameras/1/videonr = 7

cameras/2/type = capture
cameras/2/mode = mmap, rw
cameras/2/description = Virtual Camera
cameras/2/formats = 1, 2
cameras/2/videonr = 9

[Formats]
formats/size = 2

formats/1/format = YUY2
formats/1/width = 640
formats/1/height = 480
formats/1/fps = 30

formats/2/format = RGB24, YUY2
formats/2/width = 640
formats/2/height = 480
formats/2/fps = 20/1, 15/2

[Connections]
connections/size = 1
connections/1/connection = 1:2
EOF
sudo chmod -vf 644 /etc/akvcam/config.ini
```

```bash
# Running Camera
sudo modprobe videodev
sudo insmod akvcam.ko
```

## Running all tests
```bash
python3 e2e_runner.py build test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM
```

The first argument may point either directly to the directory with `test_e2e_*` binaries or to the CMake build root such as `build`. In the latter case, the runner will automatically use `build/test` when it exists.

## Running a single GTest or a pattern
All extra arguments after the required paths are forwarded to each test executable.

```bash
python3 e2e_runner.py build test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM --gtest_filter=CoreTest.listContextUsers
```

```bash
python3 e2e_runner.py build test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM --gtest_filter=CoreTest.*
```

## Passing other GTest flags
You can also pass any other GTest arguments, for example:

```bash
python3 e2e_runner.py build test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM -- --gtest_repeat=2 --gtest_break_on_failure
```

`--gtest_filter` is handled specially by the runner to decide which tests should be scheduled.

## Stopping mongo docker after tests
```bash
docker compose down
```
