

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.math.*;

class Playground {
	
	public static void main(String[] args) {
	// 	String prepend = "{\"BlockRecord\" : "; // Prepend this so later I can parse this as an object and the records as an array. Allows me to see how many records there are 
	// 	String append = "}"; // Complete the format
	// 	String s = "[  {    \"BlockID\": \"55398503-6d76-4346-b295-44ccb38ae985\",    \"Fname\": \"Helen\",    \"Lname\": \"Keller\",    \"SSNum\": \"666-45-6789\",    \"DOB\": \"1880.06.27\",    \"Diag\": \"Arthritis\",    \"Treat\": \"WarmCloths\",    \"Rx\": \"Aspirin\",    \"TimeStamp\": \" 2020-05-20.15:23:08.2\"  },  {    \"BlockID\": \"1974f1ec-b3e3-4d74-acb2-6781d306b51b\",    \"Fname\": \"Abraham\",    \"Lname\": \"Lincoln\",    \"SSNum\": \"444-45-6888\",    \"DOB\": \"1809.02.12\",    \"Diag\": \"GreviousWound\",    \"Treat\": \"Surgery\",    \"Rx\": \"Whiskey\",    \"TimeStamp\": \" 2020-05-20.15:23:09.2\"  },  {    \"BlockID\": \"b0006a4a-0203-466a-b45a-352ec0378bdf\",    \"Fname\": \"John\",    \"Lname\": \"Kennedy\",    \"SSNum\": \"333-45-6999\",    \"DOB\": \"1917.05.29\",    \"Diag\": \"AddisonsDisease\",    \"Treat\": \"DrugTherapy\",    \"Rx\": \"Steroids\",    \"TimeStamp\": \" 2020-05-20.15:23:10.2\"  },  {    \"BlockID\": \"e9e45302-b6f3-43f5-a8e9-358ae40a20b9\",    \"Fname\": \"Joe\",    \"Lname\": \"DiMaggio\",    \"SSNum\": \"111-22-3333\",    \"DOB\": \"1914.11.25\",    \"Diag\": \"SoreKnees\",    \"Treat\": \"RestFromSports\",    \"Rx\": \"Aspirin\",    \"TimeStamp\": \" 2020-05-20.15:23:11.2\"  }]";
		
	//     Socket sock;
	//     PrintStream toServer;
	//     for (int i= 0; i<3; i++) {
	//     	try {
	//     		int port = 4820+i;
	//     		sock = new Socket("localhost", port);
	//   			toServer = new PrintStream(sock.getOutputStream());
	// 	  		System.out.println("Multicasting to PID " + i + ": " + s);
	// 	  		toServer.println(s); // Multicast the input block records to all network peers
	// 	  		toServer.flush();
	// 			sock.close();
	//     	}
	//     	catch(Exception ex){
	//     		System.out.println(ex);
	//     	}
	    	
	// 	}
	// }
		// int b = Integer.parseInt("sha256", 16);

	    System.out.println('a'+1);
	}
}