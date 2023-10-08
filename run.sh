#!/bin/bash

read -p "Enter choice (CP1/CP2/HANDIN/MAKE/CLEAN): " choice
handinpack="lab1-寿晨宸-2100012945"
cd "$pwd"
case "$choice" in
  "CP1")
    cd ./checkpoints/CP1
    script -c "bash ./cp1.sh"
    cd ../..
    ;;
  "CP2")
    cd ./checkpoints/CP2
    script -c "bash ./cp2.sh"
    cd ../..
    ;;
  "HANDIN")
    mkdir -p ./"$handinpack"
    cp -r ./CMakeLists.txt ./run.sh ./src/ ./checkpoints/ ./vnetUtils/ ./"$handinpack" 
    tar -czvf "$handinpack".tar ./"$handinpack"
    rm -rf ./"$handinpack"
    ;;
   "MAKE")
    mkdir -p ./build
    cd ./build
    cmake ..
    make
    ;;
    "CLEAN")
    rm -rf ./build
    rm -rf ./checkpoints/CP1/log ./checkpoints/CP1/log
    rm -rf "$handinpack".tar
    rm -rf ./"$handinpack"
    ;;
  *)
    echo "Invalid choice. Please enter CP1/CP2/HANDIN/MAKE/CLEAN."
    ;;
esac
