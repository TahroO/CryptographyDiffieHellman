import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;

public class Client {
    private Socket s;
    private DataOutputStream dos;
    private BufferedReader br, kb;

    public Client(String hostname, int portNumber) throws IOException {
        // Create client socket
        s = new Socket(hostname, portNumber);
        initReaders();
        initOutputStream();
        sendData(kb, dos);
    }
    private void initReaders() throws IOException {
        // to read data coming from the server
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
    }

    private void initOutputStream() throws IOException {
        // to send data to the server
        dos = new DataOutputStream(s.getOutputStream());
        // to read data from the keyboard
        kb = new BufferedReader(new InputStreamReader(System.in));
    }

    private void sendData(BufferedReader keyBoardInput, DataOutputStream outputStream)
            throws IOException {
        String str, str1;
        // repeat as long as exit is typed
        while (!(str = kb.readLine()).equals("exit")) {
        // send to the server
            dos.writeBytes(str + "\n");
        // receive from the server
            str1 = br.readLine();
            System.out.println(str1);
        }
        // close connection.
        dos.close();
        br.close();
        kb.close();
        s.close();
    }
    public static void main(String args[]) throws Exception {
        Client client2 = new Client("localhost", 8000);
    }
}
