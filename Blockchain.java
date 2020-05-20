
import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;


import java.io.StringWriter;
import java.io.StringReader;

/* CDE: Encryption libraries that are needed to sign the hash: */

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.NoSuchAlgorithmException;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import java.security.spec.*;
import java.security.*;

// Produces a 64-bye string representing 256 bits of the hash output. 4 bits per character
import java.security.MessageDigest; // To produce the SHA-256 hash.


/* CDE: More helpful uitilities: */

import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.text.*;
import java.util.Base64;
import java.util.Arrays;


// Libraries needed to generate JSON 
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

// Libraries to read text files and inputs
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* We will produce something like the following BlockRecord.json file. You will marshall this record over a socket:
{
  "BlockID": "0e207d22-2598-4ff2-b471-b18c53b1005d",
  "VerificationProcessID": "Process2",
  "uuid": "0e207d22-2598-4ff2-b471-b18c53b1005d",
  "Fname": "Joseph",
  "Lname": "Chang",
  "SSNum": "123-45-6789",
  "RandomSeed": "4b14c5",
  "WinningHash": "9b209328f240c8eee79b46fbf266d02fad2e4fbe22e4279075470065b604a2de"
}
*/

class BlockRecord{
	/* The fields created when reading in incoming records */
	String BlockID;
  	String VerificationProcessID;
	String PreviousHash; // The hash that comes from the previous block
	UUID uuid; // Just to show how JSON marshals this binary data.
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;
	String RandomSeed; // The answer to solve the work - which is a guess
	String WinningHash;
	String TimeStamp;


	/* Examples of accessors for the BlockRecord fields: */
	public String getBlockID() {return BlockID;}
	public void setBlockID(String BID){this.BlockID = BID;}

	public String getVerificationProcessID() {return VerificationProcessID;}
	public void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}

	public String getPreviousHash() {return this.PreviousHash;}
	public void setPreviousHash (String PH){this.PreviousHash = PH;}

	public UUID getUUID() {return uuid;} // Later will show how JSON marshals as a string. Compare to BlockID.
	public void setUUID (UUID ud){this.uuid = ud;}

	public String getLname() {return Lname;}
	public void setLname (String LN){this.Lname = LN;}

	public String getFname() {return Fname;}
	public void setFname (String FN){this.Fname = FN;}

	public String getSSNum() {return SSNum;}
	public void setSSNum (String SS){this.SSNum = SS;}

	public String getDOB() {return DOB;}
	public void setDOB (String RS){this.DOB = RS;}

	public String getDiag() {return Diag;}
	public void setDiag (String D){this.Diag = D;}

	public String getTreat() {return Treat;}
	public void setTreat (String Tr){this.Treat = Tr;}

	public String getRx() {return Rx;}
	public void setRx (String Rx){this.Rx = Rx;}

	public String getRandomSeed() {return RandomSeed;}
	public void setRandomSeed (String RS){this.RandomSeed = RS;}

	public String getWinningHash() {return WinningHash;}
	public void setWinningHash (String WH){this.WinningHash = WH;}

	public String getTimeStamp() {return TimeStamp;}
	public void setTimeStamp(String TimeStamp) {this.TimeStamp = TimeStamp;}

	public String toString() {return BlockID + " " + Lname + " " + Fname + " " + SSNum + " " + Rx + " " + DOB + " " + Treat + " " + Diag + " " + TimeStamp;}
  
}


class BlockInput{

	private static String FILENAME;

  	PriorityBlockingQueue<BlockRecord> ourPriorityQueue = new PriorityBlockingQueue<>(4, BlockTSComparator);

	/* Token indexes for input: */
	private static final int iFNAME = 0;
	private static final int iLNAME = 1;
	private static final int iDOB = 2;
	private static final int iSSNUM = 3;
	private static final int iDIAG = 4;
	private static final int iTREAT = 5;
	private static final int iRX = 6;

	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
		@Override
		public int compare(BlockRecord b1, BlockRecord b2) {
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			return s1.compareTo(s2);
		}
    };
  
  	// args will determine the process
  	public static String getRecords() throws Exception {
  
     	LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();

    	/* CDE: Process numbers and port numbers to be used: */
    	int pnum;
	    int UnverifiedBlockPort;
	    int BlockChainPort;

		/* CDE If you want to trigger bragging rights functionality... */

		// Determine the process number
		pnum = Blockchain.PID;
		UnverifiedBlockPort = 4710 + pnum;
		BlockChainPort = 4820 + pnum;

		System.out.println("Process number: " + pnum + " Ports: " + UnverifiedBlockPort + " " + 
			       BlockChainPort + "\n");

		// Determine the process to get the right input file
		switch(pnum){
			case 1: FILENAME = "BlockInput1.txt"; break;
			case 2: FILENAME = "BlockInput2.txt"; break;
			default: FILENAME= "BlockInput0.txt"; break;
    	}

	    System.out.println("Using input file: " + FILENAME);

	    try {
	      	BufferedReader br = new BufferedReader(new FileReader(FILENAME)); // Put the file in memory buffer to read
	      	String[] tokens = new String[10];
	      	String InputLineStr;
	      	String suuid;
	      	UUID idA;
	      	BlockRecord tempRec;
	      
	      	StringWriter sw = new StringWriter();
	      
	      	int n = 0;
	      
	      	while ((InputLineStr = br.readLine()) != null) {
		
				BlockRecord BR = new BlockRecord();

				/* Timestamp the new block record first */
				try{Thread.sleep(1001);}catch(InterruptedException e){}
	      			Date date = new Date();
					//String T1 = String.format("%1$s %2$tF.%2$tT", "Timestamp:", date);
					String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
					String TimeStampString = T1 + "." + pnum; // No timestamp collisions!
					System.out.println("Timestamp: " + TimeStampString);
					BR.setTimeStamp(TimeStampString); // Stamp the new block with the time so we can sort by time

		
					/* CDE: Generate a unique blockID. This would also be signed by creating process: */
					suuid = new String(UUID.randomUUID().toString());
					BR.setBlockID(suuid);
					/* Insert the file information in the block record so we can insert it into a linkedlist */
					tokens = InputLineStr.split(" +"); // Tokenize the input 
					BR.setFname(tokens[iFNAME]);
					BR.setLname(tokens[iLNAME]);
					BR.setSSNum(tokens[iSSNUM]);
					BR.setDOB(tokens[iDOB]);
					BR.setDiag(tokens[iDIAG]);
					BR.setTreat(tokens[iTREAT]);
					BR.setRx(tokens[iRX]);

					recordList.add(BR); // Add the newly created block record to the linked list
					n++;
	      	}
	      	// System.out.println(n + " records read." + "\n");
	      	// System.out.println("Records in the linked list:");

	  //     	// Display the records the were just inserted into the records list
	  //     	Iterator<BlockRecord> iterator = recordList.iterator();
	  //     	while(iterator.hasNext()){
	  //     		tempRec = iterator.next();
			// 	System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
	  //     	} 
	  //     	System.out.println("");
	      
	  //     	iterator=recordList.iterator();
	  //     	System.out.println("The shuffled list:"); // Prove that the list is not sorted
	  //     	Collections.shuffle(recordList);
	  //     	while(iterator.hasNext()){
			// 	tempRec = iterator.next();
			// 	System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
			// } 
	  //     	System.out.println("");

	  //     	// Add the items in the list into a priority queue sorted by time
	  //     	iterator=recordList.iterator();
	  //     	System.out.println("Placing shuffled records in our priority queue...\n");
	  //     	while(iterator.hasNext()){
			// 	ourPriorityQueue.add(iterator.next());
	  //     	} 
	      
	  //     	System.out.println("Priority Queue (restored) Order:");

	   //    	while(true){ // Queue will be in TimeStamp order. (In this case, the original order.)
				// // Can't iterate here. poll() removes and returns the head of the queue.
				// tempRec = ourPriorityQueue.poll(); // For consumer thread you'll want .take() which blocks while waiting.
				// if (tempRec == null) break;
				// System.out.println(tempRec.getTimeStamp() + " " + tempRec.getFname() + " " + tempRec.getLname());
	   //    	} 
	      	System.out.println("\n\n");

	    } catch (Exception e) {e.printStackTrace();}

	    Gson gson = new GsonBuilder().setPrettyPrinting().create();
	    
	    // Convert the Java object to a JSON String:
	    String json = gson.toJson(recordList);
	    
	    System.out.println("\nJSON (shuffled) String list is: " + json);
	    
	    //Write the JSON object to a file:
	    String filename = "myList"+Blockchain.PID+".json";
	    try (FileWriter writer = new FileWriter(filename)) {
	      	gson.toJson(recordList, writer);
	    } catch (IOException e) {e.printStackTrace();}

	    return json;
	}
}

// Ports class used to assign ports and create port rules 
class Ports{
	public static int KeyServerPortBase = 4710;
	public static int UnverifiedBlockServerPortBase = 4820;
	public static int BlockchainServerPortBase = 4930;

	public static int KeyServerPort;
	public static int UnverifiedBlockServerPort;
	public static int BlockchainServerPort;

	// Method to set the ports according to our rules
	public void setPorts(){
	KeyServerPort = KeyServerPortBase + Blockchain.PID;
	UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
	BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
	}
}

// Worker thread to read in public key
class PublicKeyWorker extends Thread { 
	Socket sock; // Class member, socket, local to Worker.
	
	PublicKeyWorker (Socket s) {sock = s;} 
	
	// Read the public key that's being sent 
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = in.readLine ();
			System.out.println("Got key: " + data);
			sock.close(); 
		} catch (IOException x){x.printStackTrace();}
	}
}

// Public key server to listen for incoming connection sending their public key 
class PublicKeyServer implements Runnable {
  //public ProcessBlock[] PBlock = new ProcessBlock[3]; // One block to store info for each process.
    
    public void run(){
    	int q_len = 6;
    	Socket sock;
    	System.out.println("Starting Key Server input thread using " + Integer.toString(Ports.KeyServerPort));
    	try {
    		ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, q_len);
      		while (true) {
				sock = servsock.accept();
				new PublicKeyWorker (sock).start(); // Fire off thread to read public key
      		}
    	} catch (IOException ioe) {System.out.println(ioe);}
	}
}

// Unverified block server to listen for incoming connection requesting to add to unvierified block
class UnverifiedBlockServer implements Runnable {
	PriorityBlockingQueue<BlockRecord> queue;

	// Assign the queue globally
	UnverifiedBlockServer(PriorityBlockingQueue<BlockRecord> queue) {
		this.queue = queue;
  	}

  	/* Inner class to share priority queue. We are going to place the unverified blocks into this queue in the order we get
     them, but they will be retrieved by a consumer process sorted by blockID. */ 

     // Worker thread to add data to unverified queue
  	class UnverifiedBlockWorker extends Thread { 
    	Socket sock; 
    	
    	UnverifiedBlockWorker (Socket s) {sock = s;} // Assign the socket connection
    	
    	public void run() {
      		try {
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				String incomingBlocks = in.readLine();
				String data = "";
				while (incomingBlocks != null) {
					data += incomingBlocks;
					incomingBlocks = in.readLine();
				}
				String prepend = "{\"BlockRecords\" : "; // Prepend this so later I can parse this as an object and the records as an array. Allows me to see how many records there are 
				String append = "}"; // Complete the format
				String formattedJson = prepend + data + append; // Generate the json string with additional formatting
				final JSONObject obj = new JSONObject(formattedJson); // Convert json string to object for simpler retrieval
		    	final JSONArray blockRecords = obj.getJSONArray("BlockRecords"); // Get the block records
		    	final int n = blockRecords.length(); // Compute how many block records there are
		    	for (int i = 0; i < n; ++i) { // Loop block records json array, create a block record from each block record json object, and insert it into queue
		      		final JSONObject blockRecord = blockRecords.getJSONObject(i); // Get the current block record
					// Convert the current block record from json to java object
					BlockRecord BR = new BlockRecord();
					BR.setBlockID(blockRecord.getString("BlockID"));
					BR.setFname(blockRecord.getString("Fname"));
					BR.setLname(blockRecord.getString("Lname"));
					BR.setSSNum(blockRecord.getString("SSNum"));
					BR.setDOB(blockRecord.getString("DOB"));
					BR.setDiag(blockRecord.getString("Diag"));
					BR.setTreat(blockRecord.getString("Treat"));
					BR.setRx(blockRecord.getString("Rx"));
					BR.setTimeStamp(blockRecord.getString("TimeStamp"));

					System.out.println("Put in priority queue: " + data + "\n"); 
					queue.put(BR); // Put block record in priority queue (wait until there is space if full or free if busy)
			    }
				sock.close(); 
      		} catch (Exception x){x.printStackTrace();}
    	}
  	}
  
  	public void run(){
    	int q_len = 6; /* The amount of simultaneous connections allowed */
    	Socket sock;
    	System.out.println("Starting the Unverified Block Server input thread using " + Integer.toString(Ports.UnverifiedBlockServerPort));
    	try {
      		ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, q_len);
      		while (true) {
				sock = servsock.accept(); // Listen for new unverified blocks connection requests
				new UnverifiedBlockWorker(sock).start(); // Fire off a thread to start the request
      		}
    	} catch (IOException ioe) {System.out.println(ioe);}
  	}
}


// The purpose of this class is to retrieve unverified blocks from the queue and begin to solve 
// the work. If solved by the process, that process will multicast the new blockchain to peers
class UnverifiedBlockConsumer implements Runnable {
	PriorityBlockingQueue<BlockRecord> queue;
  	int PID;
  	
  	UnverifiedBlockConsumer(PriorityBlockingQueue<BlockRecord> queue){
    	this.queue = queue; // Make the queue publicly accessible.
  	}

  	// Continuously loop and remove unverified blocks from the queue and multicast the new blockchain if solved
  	public void run(){
	    BlockRecord blockRecord;
	    PrintStream toServer;
	    Socket sock;
	    String newblockchain;
	    String fakeVerifiedBlock;

	    /* The fields created when reading in incoming records */
		String BlockID;
		String VerificationProcessID;
		String PreviousHash; // The hash that comes from the previous block
		UUID uuid; // Just to show how JSON marshals this binary data.
		String Fname;
		String Lname;
		String SSNum;
		String DOB;
		String Diag;
		String Treat;
		String Rx;
		String RandomSeed; // The answer to solve the work - which is a guess
		String WinningHash;
		String TimeStamp;

	    System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
    	try{
      		while(true){ // Consume from the incoming queue. Do the work to verify. Mulitcast new blockchain
				blockRecord = queue.take(); // Remove oldiest block record from queue (wait for the next item if the queue is empty)
				System.out.println("Consumer got unverified: " + blockRecord.toString());
				Fname = blockRecord.getFname();
				Lname = blockRecord.getLname();
				SSNum = blockRecord.getSSNum();
				DOB = blockRecord.getDOB();
				Diag = blockRecord.getDiag();
				Treat = blockRecord.getTreat();
				Rx = blockRecord.getRx();

				/// MARSHAL IT TO BLOCKCHAIN SERVER AS JSON

				// Ordindarily we would do real work here, based on the incoming data.
				int j; // Here we fake doing some work (That is, here we could cheat, so not ACTUAL work...)
				for(int i=0; i< 100; i++){ // put a limit on the fake work for this example
					j = ThreadLocalRandom.current().nextInt(0,10);
					try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}
					if (j < 3) break; // <- how hard our fake work is; about 1.5 seconds.
				}	
	
			/* With duplicate blocks that have been verified by different procs ordinarily we would keep only the one with
          	 the lowest verification timestamp. For the exmple we use a crude filter, which also may let some dups through */
				if(Blockchain.blockchain.indexOf(blockRecord.toString().substring(1, 50)) < 0){ // Crude, but excludes most duplicates. 
				  	fakeVerifiedBlock = "[" + blockRecord + " verified by P" + Blockchain.PID + " at time " 
				    + Integer.toString(ThreadLocalRandom.current().nextInt(100,1000)) + "]\n";
				    System.out.println(fakeVerifiedBlock);
				  	String tempblockchain = fakeVerifiedBlock + Blockchain.blockchain; // add the verified block to the chain
				  	for(int i=0; i < Blockchain.numProcesses; i++){ // multicast the new proposed blockchain to the group including this process:
					    sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
					    toServer = new PrintStream(sock.getOutputStream());
					    toServer.println(tempblockchain); toServer.flush(); // make the multicast
					    sock.close();
				  	}
				}
				Thread.sleep(1500); // For the example, wait for our blockchain to be updated before processing a new block
			}
		} catch (Exception e) {System.out.println(e);}
	}
}
    
 // Blockchain worker thread to verify new  blockchain that are expectedly the winners
class BlockchainWorker extends Thread { 
	Socket sock; 
	BlockchainWorker (Socket s) {sock = s;} 

	public void run(){
    	try{
      		BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = "";
			String data2;
			while((data2 = in.readLine()) != null){
				data = data + data2;
			}
			// Do check again to see if someone has just added this block to the chain
			if(Blockchain.blockchain.indexOf(data.substring(1, 50)) < 0){	
				Blockchain.blockchain = data; // This is where we would normally verify if the block is legitimate
				System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchain + "\n\n");
			}
			sock.close(); 
	    } catch (IOException x){x.printStackTrace();}
	}
}

// A server to listen and accept incoming blockchains that will replace the old blockchain if winner.
class BlockchainServer implements Runnable {
	public void run(){
    	int q_len = 6; /* The number of allowed simultaneous conenctions */
    	Socket sock;
	    System.out.println("Starting the blockchain server input thread using " + Integer.toString(Ports.BlockchainServerPort));
	    try{
	    	ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, q_len);
	    	while (true) {
	    		sock = servsock.accept();
	    		new BlockchainWorker (sock).start(); 
      		}
    	}catch (IOException ioe) {System.out.println(ioe);}
  	}
}



class Blockchain {
	static String serverName = "localhost";
	static String blockchain = "[First block]";
	static int numProcesses = 3; // This equates to the number of processes that will be executed from our batch file (also known as peers)
	static int PID = 0; // Default process ID

	public void Multicast (){ // A method to send (multicast) data to the processes in the group (in this case, every process is in the group).
	    Socket sock;
	    PrintStream toServer;

	    try{
	    	for(int i=0; i< numProcesses; i++){ // multicast the public to all network peers public key server.
	    		sock = new Socket(serverName, Ports.KeyServerPortBase + i); 
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println("FakeKeyProcess" + Blockchain.PID); toServer.flush();
				sock.close();
			} 
			Thread.sleep(1000); // Wait for the server to process the keys - this could be an acknowledgement instead of a sleep
			String recordList = BlockInput.getRecords(); // Get the input records and multicast it to all processes in json format
	      	for(int i=0; i< numProcesses; i++){
	      		sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
	      		toServer = new PrintStream(sock.getOutputStream());
	      		System.out.println("Multicasting to PID " + i + ": " + recordList);
	      		toServer.println(recordList);
	      		toServer.flush();
				sock.close();
		    }	

	    }catch (Exception x) {x.printStackTrace ();}
	}

	// Implement comparator to sort by the timestamp field in a block record object
	public static Comparator<BlockRecord> BlockTSComparator = new Comparator<BlockRecord>() {
		@Override
		public int compare(BlockRecord b1, BlockRecord b2) {
			String s1 = b1.getTimeStamp();
			String s2 = b2.getTimeStamp();
			if (s1 == s2) {return 0;}
			if (s1 == null) {return -1;}
			if (s2 == null) {return 1;}
			return s1.compareTo(s2);
		}
    };


	public static void main(String args[]){
		int q_len = 6; /* The number of allowed simultaneous conenctions */
		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Extract the Process ID from the arguments
	
		System.out.println("Luis's BlockFramework control-c to quit.\n");
		System.out.println("Using processID " + PID + "\n");

		final PriorityBlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>(4, BlockTSComparator); // Create a blocking priority queue to store and retrieve unverified blocks concurrently 
		new Ports().setPorts(); // Set the ports according to the rules assigned 
		new Thread(new PublicKeyServer()).start(); // Start a thread to read and process incoming public keys
		new Thread(new UnverifiedBlockServer(queue)).start(); // Start a thread to process incoming unverified blocks
		new Thread(new BlockchainServer()).start(); // Start a thread to process incoming new blockchains
		try{Thread.sleep(2000);}catch(Exception e){} // Wait for servers to start.
		new Blockchain().Multicast(); // Multicast some new unverified blocks out to all servers as data
		try{Thread.sleep(1000);}catch(Exception e){} // Wait for multicast to fill incoming queue for our example.
		new Thread(new UnverifiedBlockConsumer(queue)).start(); // Start a thread to process the unverified blocks in the queue
	}

}