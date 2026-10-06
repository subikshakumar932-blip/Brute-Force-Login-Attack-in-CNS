/* Simulates a legitimate user logging in with the correct password. */
import java.io.*;
import java.net.*;

public class LegitUser {
    static final String HOST = "127.0.0.1";
    static final int PORT = 6001;

    static String attempt(String user, String pass) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(HOST, PORT), 3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            byte[] ub = user.getBytes(); out.writeShort(ub.length); out.write(ub);
            byte[] pb = pass.getBytes(); out.writeShort(pb.length); out.write(pb);
            DataInputStream in = new DataInputStream(s.getInputStream());
            return in.readUTF();
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=".repeat(62));
        System.out.println("   LEGITIMATE USER - login with correct credentials");
        System.out.println("=".repeat(62));
        String r = attempt("suruthi", "SecureNet#99");
        System.out.println("[*] login 'suruthi' with correct password -> " + r);
    }
}
