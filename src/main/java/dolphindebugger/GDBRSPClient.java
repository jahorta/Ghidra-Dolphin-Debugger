package dolphindebugger;

import java.io.*;
import java.net.*;

public class GDBRSPClient {
    private Socket socket;
    private BufferedReader reader;
    private BufferedWriter writer;

    public void connect(String host, int port) throws IOException {
        socket = new Socket(host, port);
        reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
        System.out.println("Connected to GDB stub at " + host + ":" + port);
    }

    public void close() throws IOException {
        socket.close();
    }
    
    public boolean isConnected() {
        return socket != null && socket.isConnected() && !socket.isClosed();
    }

    private String checksum(String data) {
        int sum = 0;
        for (char ch : data.toCharArray()) {
            sum += ch;
        }
        return String.format("%02x", sum & 0xff);
    }

    public void sendPacket(String data) throws IOException {
        String packet = "$" + data + "#" + checksum(data);
        writer.write(packet);
        writer.flush();
        System.out.println("Sent: " + packet);
    }

    public String readPacket() throws IOException {
        int ch;
        // Wait for start of packet
        while ((ch = reader.read()) != -1) {
            if (ch == '$') break;
        }

        if (ch == -1) return null;

        StringBuilder data = new StringBuilder();
        while ((ch = reader.read()) != -1 && ch != '#') {
            data.append((char) ch);
        }

        if (ch == -1) return null;

        // Read the checksum
        int c1 = reader.read();
        int c2 = reader.read();

        if (c1 == -1 || c2 == -1) return null;

        String receivedChecksum = "" + (char) c1 + (char) c2;
        String calculatedChecksum = checksum(data.toString());

        if (!receivedChecksum.equalsIgnoreCase(calculatedChecksum)) {
            System.err.println("Checksum mismatch: " + data + " != " + receivedChecksum);
            writer.write("-");
            writer.flush(); // Send NAK
            return null;
        }
		writer.write("+");
		writer.flush(); // Send ACK

        System.out.println("Received: " + data.toString());
        return data.toString();
    }
}