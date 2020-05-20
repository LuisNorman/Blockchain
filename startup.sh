#!/bin/bash
javac -cp "gson-2.8.2.jar:json.jar" Blockchain.java
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar:json.jar\" Blockchain 0" &
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar:json.jar\" Blockchain 1" &
gnome-terminal -- sh -c "java -cp \".:gson-2.8.2.jar:json.jar\" Blockchain 2" &