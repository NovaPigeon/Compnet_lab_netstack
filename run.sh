#!/bin/bash

read -p "Enter choice (CP{1-10}/HANDIN/MAKE/CLEAN): " choice
handinpack="lab3-寿晨宸-2100012945"

case "$choice" in
  "CP1")
    cd ./checkpoints/CP1 || exit
    script -c "bash ./cp1.sh"
    cd ../..
    ;;
  "CP2")
    cd ./checkpoints/CP2 || exit
    script -c "bash ./cp2.sh"
    cd ../..
    ;;
  "CP3")
    cd ./checkpoints/CP3 || exit
    script -c "bash ./cp3.sh"
    cd ../..
    ;;
  "CP4")
    cd ./checkpoints/CP4 || exit
    script -c "bash ./cp4.sh"
    cd ../..
    ;;
  "CP5")
    cd ./checkpoints/CP5 || exit
    script -c "bash ./cp5.sh"
    cd ../..
    ;;
  "CP6")
    cd ./checkpoints/CP6 || exit
    script -c "bash ./cp6.sh"
    cd ../..
    ;;
  "CP7")
    cd ./checkpoints/CP7 || exit
    script -c "bash ./cp7.sh"
    cd ../..
    ;;
  "CP8")
    cd ./checkpoints/CP8 || exit
    script -c "bash ./cp8.sh"
    cd ../..
    ;;
  "CP9")
    cd ./checkpoints/CP9 || exit
    script -c "bash ./cp9.sh"
    cd ../..
    ;;
  "CP10")
    cd ./checkpoints/CP10 || exit
    script -c "bash ./cp10.sh"
    cd ../..
    ;;
  "HANDIN")
    mkdir -p ./"$handinpack"
    cp -r ./CMakeLists.txt ./run.sh ./src/ ./checkpoints/CP7 ./checkpoints/CP8 ./checkpoints/CP9 ./checkpoints/CP10 ./vnetUtils/ ./README.md ./README.pdf ./not-implemented.pdf ./"$handinpack"
    cd ./"$handinpack" || exit 
    mkdir -p checkpoints
    mv ./CP* ./checkpoints
    cd ..
    tar -czvf "$handinpack".tar ./"$handinpack"
    rm -rf ./"$handinpack"
    ;;
   "MAKE")
    mkdir -p ./build
    cd ./build || exit
    cmake ..
    make
    ;;
    "CLEAN")
    rm -rf ./build
    rm -rf checkpoints/CP*/log checkpoints/CP*/typescript
    rm -rf checkpoints/CP*/*.pcap
    rm -rf "$handinpack".tar
    rm -rf ./"$handinpack"
    ;;
  *)
    echo "Invalid choice. Please enter CP{1-10}/HANDIN/MAKE/CLEAN."
    ;;
esac
