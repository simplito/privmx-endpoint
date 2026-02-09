# A helper project with the End 2 End tests for the PrivMX Endpint core library
## Building tests
### Using Conan
```
./build.sh
```

when you using conan make sure to set correct version of privmx-endpoint in ```conanfile.txt```
### Using system lib
```
mkdir build
cd build
cmake ..
cmake --build . -- -j20
```

## Creating dataset
To create dataset required for testing you need run
```./test_env/create_dataset/main.sh```
, to list advanced options in creation tool
```./test_env/create_dataset/main.sh --help```

Dataset by default will be created in ```test_env/create_dataset``` with name ```Dataset_YYYY-mm-dd_HH-MM```
## Running tests
When you using conan remember to use ```conanrun.sh``` or all tests will fail
### Setup mongo docker
```
docker compose up -d
```
### Tests
```
python3 e2e_runner.py "build" "test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM/ServerData.ini" "test_env/create_dataset/Dataset_YYYY-mm-dd_HH-MM"
```
### Stoping mongo docker after tests
```
docker compose down
```

## 



