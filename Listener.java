import java.io.DataInputStream;
import java.io.IOException;

public class Listener implements Runnable{
        private DataInputStream in;
        public Listener (DataInputStream in){
            this.in = in;
        }

        public void run() {
            boolean loop = true;
            do {
                try {
                    int receivedBytesLength = in.readInt();
                    byte[] receivedBytes = new byte[receivedBytesLength];
                    in.read(receivedBytes);
                    System.out.println(receivedBytes);
                    

                } catch (IOException e) {
                    e.printStackTrace();
                }    
            } while (loop); 
            
        }
    }