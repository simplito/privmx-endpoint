# Creating dataset
To create dataset required for testing you need run
```./test_env/create_dataset/main.sh```
, to list advanced options in creation tool
```./test_env/create_dataset/main.sh --help```

Dataset by default will be created in ```test_env/create_dataset``` with name ```Dataset_YYYY-mm-dd_HH-MM```
# Running tests
When you using conan remember to use ```conanrun.sh``` or all tests will fail
## Setup mongo docker
```
docker compose up -d
```
### Stream Api requirements
Minimum one Video device, witch is streaming data
### Example setup 

```
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
```
# Running Camera
sudo modprobe videodev
sudo insmod akvcam.ko
```


## Running Tests
```
python3 e2e_runner.py "build" "test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini" "test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM"
```

## Stoping mongo docker after tests
```
docker compose down
```
## 



