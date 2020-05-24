
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
import java.nio.charset.StandardCharsets; // To produce utf_8 bytes array

/* CDE: More helpful uitilities: */
import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.text.*;
import java.util.Base64;
import java.util.Arrays;

import java.math.BigInteger;
import java.lang.Math;


// Libraries needed to generate JSON 
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

// Libraries to read text files and inputs
import java.io.FileWriter;
import java.io.IOException;
import java.io.FileReader;
import java.io.Reader;

// https://www.javatpoint.com/java-get-current-date
import java.time.format.DateTimeFormatter;  
import java.time.LocalDateTime;    

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
	String CreationProcess; // Used to label which process created the block record


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

	public String getCreationProcess() {return CreationProcess;}
	public void setCreationProcess(String pnum){this.CreationProcess = pnum;}

	public String toString() {return BlockID + " " + Lname + " " + Fname + " " + SSNum + " " + Rx + " " + DOB + " " + Treat + " " + Diag + " " + TimeStamp;}
  
  	public String calculateBlockHash(String randomSeed) throws NoSuchAlgorithmException {
  		
  		String str = this.PreviousHash + this.Fname + this.Lname + this.SSNum + this.DOB + this.Diag + this.Treat + this.Rx + 
  					this.TimeStamp + randomSeed;

  		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		byte[] encodedhash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
		String encryptedData = bytesToHex(encodedhash);
		
		return encryptedData;
  	}

  	private static String bytesToHex(byte[] hash) {
    	StringBuffer hexString = new StringBuffer();
    	for (int i = 0; i < hash.length; i++) {
    		String hex = Integer.toHexString(0xff & hash[i]);
    		if(hex.length() == 1) hexString.append('0');
        		hexString.append(hex);
    	}
    	return hexString.toString();
	}
}

class Key {

	static PrivateKey privateKey;
	static PublicKey publicKey;

	static HashMap<Integer, PrivateKey> privateKeys = new HashMap<>();
	static HashMap<Integer, PublicKey> publicKeys = new HashMap<>();

	// http://www.java2s.com/Tutorial/Java/0490__Security/GeneratingaPublicPrivateKeyPair.htm

	public void setKeys() throws NoSuchAlgorithmException {

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	    keyGen.initialize(1024); // Set the key siz
    	KeyPair keypair = keyGen.genKeyPair(); // Generate new private/public key pair

	    privateKey = keypair.getPrivate(); // Assign private key
	    // 	// System.out.println(privateKey);

	   	publicKey = keypair.getPublic(); // Assign public key
	    // 	// System.out.println(publicKey);

	}

	// Method to get the instance of this object's key
	public static PublicKey getPublicKey() {
		return publicKey;
	}

	// Method to get the public key of specific network peers
	public static PublicKey getPublicKey(int pnum) {
		return publicKeys.get(pnum);
	}

	// Method to set the public of specific network peers
	public void setKey(int pnum, PublicKey publicKey) {
		publicKeys.put(pnum, publicKey);
	}

	// Method to sign document using this instance's private key
	public String signDocument(String document) throws NoSuchAlgorithmException {
		String signedDocument = "";
		Signature signature = Signature.getInstance("SHA256withRSA"); // Create signature object using SHA256 w RSA
		// Init signature using the instance's private key
		try {signature.initSign(privateKey);} 
		catch (Exception ex) {System.out.println(ex);}
		
		

		return signedDocument;

	}


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

    private static String bytesToHex(byte[] hash) {
    	StringBuffer hexString = new StringBuffer();
    	for (int i = 0; i < hash.length; i++) {
    		String hex = Integer.toHexString(0xff & hash[i]);
    		if(hex.length() == 1) hexString.append('0');
        		hexString.append(hex);
    	}
    	return hexString.toString();
	}
  
  	// args will determine the process
  	public static String getRecords() throws Exception {
  
     	LinkedList<BlockRecord> recordList = new LinkedList<BlockRecord>();

    	/* CDE: Process numbers and port numbers to be used: */
    	int pnum;
	    int UnverifiedBlockPort;
	    int BlockChainPort;

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
	      
	      	int n = 0;
	      
	      	while ((InputLineStr = br.readLine()) != null) {
		
				
				/* Convert the file information into a block record (java object) */

				BlockRecord BR = new BlockRecord();

				/* Timestamp the new block record first */
				try{Thread.sleep(1001);}catch(InterruptedException e){}

	      			Date date = new Date();
					//String T1 = String.format("%1$s %2$tF.%2$tT", "Timestamp:", date);
					String T1 = String.format("%1$s %2$tF.%2$tT", "", date);
					String TimeStampString = T1 + "." + pnum; // No timestamp collisions!
					BR.setTimeStamp(TimeStampString); // Stamp the new block with the time so we can sort by time

					/* CDE: Generate a unique blockID. And also sign it by the creating process. */
					suuid = new String(UUID.randomUUID().toString());
					MessageDigest digest = MessageDigest.getInstance("SHA-256");
					byte[] encodedhash = digest.digest(suuid.getBytes(StandardCharsets.UTF_8));
					String sha256 = bytesToHex(encodedhash);
					String hashed_suuid = sha256.substring(sha256.length()-16);
					BR.setBlockID(hashed_suuid);

					// Finish setting the others fields
					tokens = InputLineStr.split(" +"); // Tokenize the input 
					BR.setFname(tokens[iFNAME]);
					BR.setLname(tokens[iLNAME]);
					BR.setSSNum(tokens[iSSNUM]);
					BR.setDOB(tokens[iDOB]);
					BR.setDiag(tokens[iDIAG]);
					BR.setTreat(tokens[iTREAT]);
					BR.setRx(tokens[iRX]);
					BR.setCreationProcess(String.valueOf(Blockchain.PID)); 

					recordList.add(BR); // Add the newly created block record to the linked list
					n++;
	      	}

	      	System.out.println("\n\n");

	    } catch (Exception e) {e.printStackTrace();}

	    // Convert the Java object to a JSON String:
	    Gson gson = new GsonBuilder().setPrettyPrinting().create();
	    String json = gson.toJson(recordList);

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
	Socket sock; // Create socket to read in input from sending process that's connected to the socket as well
	
	PublicKeyWorker (Socket s) {sock = s;} 
	
	// Read the public key that's being sent 
	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String publicKey = "";
			String data;
			while((data = in.readLine()) != null) {
				publicKey += data;
			}

			System.out.println("Got public key: " + publicKey);
			sock.close(); 
		} catch (IOException x){x.printStackTrace();}
	}
}

// Public key server to listen for incoming connection sending their public key 
class PublicKeyServer implements Runnable {

	// Listen and accept incoming connection the public key server
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

// Unverified block server: Listens for incoming connections to add to unverified block
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

      			/* Read in the unverified blocks array and add it to the queue */
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				String incomingBlocks = in.readLine();
				String data = "";
				while (incomingBlocks != null) {
					data += incomingBlocks;
					incomingBlocks = in.readLine();
				}

				// Convert the marshaled json array to a block records array
		    	Gson gson = new Gson();
		    	BlockRecord[] arr = gson.fromJson(data, BlockRecord[].class);

		    	// Put each block in the block array in the unverified queue
		    	for (int i = 0; i < arr.length; i++) { // Loop block records json array, create a block record from each block record json object, and insert it into queue
					System.out.println("Put in priority queue: " + arr[i].toString() + "\n"); 
					queue.put(arr[i]); // Put block record in priority queue (wait until there is space if full or free if busy)
			    }
				sock.close(); // close socket connection
      		} catch (Exception x){x.printStackTrace();}
    	}
  	}
  
  	// Listen and accept connections to the unverified block server
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

	private static Boolean isWinningHash(String hash) {
		String hexLine = "0123456789ABCDEF";
		int decimal = 0;
		for (int i=0; i<hash.length(); i++) {
			char current_char = hash.charAt(i);
			int addition = hexLine.indexOf(current_char);
			decimal += 16 * decimal + addition;
			if (decimal < 10000)
				return false;
			System.out.println("\n\n\n\n\n\nWINNER: " + Blockchain.PID);
		}
		return true;

	}

	public Boolean isAdded(BlockRecord blockRecord) {
		// Set the current block record's previous hash by getting the current blockchain, extracting the last added block, and the winning hash value
		String json = "[" + Blockchain.blockchain + "]";
		Gson gson2 = new Gson();
		BlockRecord[] arr = gson2.fromJson(json, BlockRecord[].class);

		for (int i=0; i<arr.length; i++) {
			if (blockRecord.getBlockID() == arr[i].getBlockID())
				return true;
		}

		return false;

	}

  	// Continuously loop and remove unverified blocks from the queue and multicast the new blockchain if solved
  	public void run(){
	    BlockRecord blockRecord = null;
	    PrintStream toServer;
	    Socket sock;
	    String fakeVerifiedBlock;

	 //    /* The fields created when reading in incoming records */
		// String BlockID;
		// String VerificationProcessID;
		// String PreviousHash; // The hash that comes from the previous block
		// UUID uuid; // Just to show how JSON marshals this binary data.
		// String Fname;
		// String Lname;
		// String SSNum;
		// String DOB;
		// String Diag;
		// String Treat;
		// String Rx;
		// String RandomSeed; // The answer to solve the work - which is a guess
		// String WinningHash;
		// String TimeStamp;

	    System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
    	try{
      		while(true){ // Consume from the incoming queue. Do the work to verify. Mulitcast new blockchain	

		    	blockRecord = queue.take(); // Remove oldest block from the queue

				System.out.println("Consumer got unverified: " + blockRecord.toString());

				/* https://www.baeldung.com/sha-256-hashing-java */

				for(int i=0; i < 100; i++){ // add time constraint on how long the puzzle can take at max
					if (isAdded(blockRecord)) // Check if block record was recently added
						blockRecord = queue.take(); // If so, get another block record
					String randomSeed = ThreadLocalRandom.current().nextInt(0,81); // Generate a random seed
					String hash = blockRecord.calculateBlockHash(randomSeed); // Compute new possible winning hash

					if isWinningHash(hash.substring(hash.length()-16)) { // Check if last 16 bits of hash value is less than 5000 which equals winner
						break; // Found the winning hash
					}

					try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}
				}

				// Ordindarily we would do real work here, based on the incoming data.
				// int j; // Here we fake doing some work (That is, here we could cheat, so not ACTUAL work...)
				// for(int i=0; i< 100; i++){ // add time constraint on how long the puzzle can take at max
				// 	j = ThreadLocalRandom.current().nextInt(0,10);
				// 	try{Thread.sleep(500);}catch(Exception e){e.printStackTrace();}
				// 	if (j < 3) break; // <- how hard our fake work is; about 1.5 seconds.
				// }	
	
				if(!isAdded(blockRecord)){ // Check if the block id has been recently inserted in the blockchain
					blockRecord.setRandomSeed(randomSeed); // Set the block's random string
					blockRecord.setWinningHash(hash);
					blockRecord.setVerificationProcessID(String.valueOf(Blockchain.PID));
					DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss.SSS");  
					LocalDateTime now = LocalDateTime.now();  
				  	fakeVerifiedBlock = "\n-[Block ID: " + blockRecord.getBlockID() + " verified by P" + Blockchain.PID + " at time " + dtf.format(now) + "]\n";
				  	System.out.println(fakeVerifiedBlock);

					// Convert the block record (java) object into a json object and send to peers
					Gson gson = new GsonBuilder().setPrettyPrinting().create();
					String jsonBlock = gson.toJson(blockRecord);
					fakeVerifiedBlock = jsonBlock;

					// Multicast the proposed new block to all peers
				  	String tempblockchain = fakeVerifiedBlock + "," +Blockchain.blockchain; // add the verified block to the chain
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
    
 // Blockchain worker thread to verify new proposed blocks and adds it to blockchain if verified
class BlockchainWorker extends Thread { 
	Socket sock; 
	BlockchainWorker (Socket s) {sock = s;} 

	public void run(){
    	try{

    		// Read in the new proposed unverified block
      		BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = "";
			String data2;
			while((data2 = in.readLine()) != null){
				data = data + data2;
			}

			if(Blockchain.blockchain.indexOf(data.substring(1, 50)) < 0){ // Avoids duplicates	

				// Complete the format of the json array and then convert it to Block Records Array (Java Object Array)
				String json = "[" + data + "]";
				Gson gson2 = new Gson();
		    	BlockRecord[] arr = gson2.fromJson(json, BlockRecord[].class);
		    	BlockRecord verifiedBlock = arr[0];

				Blockchain.blockchain = data; // This is where we would normally verify if the block is legitimate
				System.out.println("         --NEW BLOCKCHAIN--\n" + Blockchain.blockchain + "\n\n");

				// If process 0: write shared blockchain ledger to disk
				if (Blockchain.PID == 0) { 
				    //Write the JSON object to a file:
				    String filename = "BlockchainLedger.json";
				    try (FileWriter writer = new FileWriter(filename)) {
				    	Gson gson = new GsonBuilder().setPrettyPrinting().create();
				      	gson.toJson(arr, writer);
				    } catch (IOException e) {e.printStackTrace();}
				}
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
	static String blockchain = "{\"BlockID\": \"0\", \"WinningHash\": \"0\"}";
	static int numProcesses = 3; // This equates to the number of processes that will be executed from our batch file (also known as peers)
	static int PID = 0; // Default process ID

	public void Multicast (){ // A method to send (multicast) data to the processes in the group (in this case, every process is in the group).
	    Socket sock;
	    PrintStream toServer;

	    try{
	    	for(int i=0; i< numProcesses; i++){ // multicast the public key to all network peers public key server.
	    		sock = new Socket(serverName, Ports.KeyServerPortBase + i); 
				toServer = new PrintStream(sock.getOutputStream());
				toServer.println("{\"Process ID\": " + "\"" + PID + "\"" + ", PublicKey: " + "\"" + Key.getPublicKey() +  "\"" + "}"); 
				toServer.flush(); // Send the process id and public key so other processes can verify you.
				sock.close();
			} 
			Thread.sleep(1000); // Wait for the server to process the keys - this could be an acknowledgement instead of a sleep
			String inputBlockRecords = BlockInput.getRecords(); // Get the input records and multicast it to all processes in json format
	      	for(int i=0; i< numProcesses; i++){
	      		sock = new Socket(serverName, Ports.UnverifiedBlockServerPortBase + i);
	      		toServer = new PrintStream(sock.getOutputStream());
	      		System.out.println("Multicasting to PID " + i + ": " + inputBlockRecords);
	      		toServer.println(inputBlockRecords); // Multicast the input block records to all network peers
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


	public static void main(String args[]) throws NoSuchAlgorithmException { // Must handle exception for invoking setKeys() which generates key pairs
		int q_len = 6; /* The number of allowed simultaneous conenctions */
		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Extract the Process ID from the arguments
	
		System.out.println("Luis's BlockFramework control-c to quit.\n");
		System.out.println("Using processID " + PID + "\n");

		final PriorityBlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>(4, BlockTSComparator); // Create a blocking priority queue to store and retrieve unverified blocks concurrently 
		new Ports().setPorts(); // Set the ports according to the rules assigned 
		new Key().setKeys(); // Set the public and private key
		new Thread(new PublicKeyServer()).start(); // Start a thread to read and process incoming public keys
		new Thread(new UnverifiedBlockServer(queue)).start(); // Start a thread to process incoming unverified blocks
		new Thread(new BlockchainServer()).start(); // Start a thread to process incoming new blockchains
		try{Thread.sleep(2000);}catch(Exception e){} // Wait for servers to start.
		new Blockchain().Multicast(); // Multicast some new unverified blocks out to all servers as data
		try{Thread.sleep(5000);}catch(Exception e){} // Wait for multicast to fill incoming queue for our example.
		new Thread(new UnverifiedBlockConsumer(queue)).start(); // Start a thread to process the unverified blocks in the queue
	}

}