
tell application "Terminal.app"

   activate

   set targetWindow to 0

   tell application "System Events" to keystroke "n" using command down

   do script "cd /Users/luis/Desktop/DePaul/DistributedSystems/Assignment3/Blockchain && javac -cp \"gson-2.8.2.jar\" Blockchain.java && java -cp \".:gson-2.8.2.jar\" Blockchain 0" in front window

   delay 0.1

   tell application "System Events" to keystroke "n" using command down

   do script "cd /Users/luis/Desktop/DePaul/DistributedSystems/Assignment3/Blockchain && java -cp \".:gson-2.8.2.jar\" Blockchain 1" in front window

   delay 0.1

   tell application "System Events" to keystroke "n" using command down

   do script "cd /Users/luis/Desktop/DePaul/DistributedSystems/Assignment3/Blockchain && java -cp \".:gson-2.8.2.jar\" Blockchain 2" in front window

end tell