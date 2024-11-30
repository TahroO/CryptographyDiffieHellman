import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;

public class Server {

    private BufferedReader clientReader, keyBoardReader;
    private final ServerSocket serverSocket;
    private final Socket clientSocket;
    private final PrintStream clientPrintStream;


    public Server(int portNumber) throws IOException {
        serverSocket = new ServerSocket(portNumber);
        clientSocket = waitForClient();
        initReader(clientSocket);
        clientPrintStream = new PrintStream(clientSocket.getOutputStream());
        handleInput();
    }
    private void initReader(Socket clientSocket) throws IOException{
        clientReader = new BufferedReader(new
                InputStreamReader(clientSocket.getInputStream()));
        keyBoardReader = new BufferedReader(new InputStreamReader(System.in));
    }
    private Socket waitForClient() throws IOException {
        System.out.println("Wait for Client");
        Socket socket = serverSocket.accept();
        System.out.println("Connection established");
        return socket;
    }
    private void handleInput() throws IOException {
        while (true) {
            String str, str1;
            while ((str = clientReader.readLine()) != null) {
                System.out.println(str);
                str1 = keyBoardReader.readLine();
                clientPrintStream.println(str1);
            }
            clientPrintStream.close();
            clientReader.close();
            keyBoardReader.close();
            serverSocket.close();
            clientSocket.close();
            // terminate application
            System.exit(0);
        }
    }
    public static void main(String[] args) {
        try {
            Server server = new Server(8000);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
