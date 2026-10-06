/* Brute-Force Login Attack Detection System - ATTACKER (demo script) */
import java.io.*;
import java.net.*;

public class Attacker {
    static final String HOST = "127.0.0.1";
    static final int PORT = 6001;
    static final String USERNAME = "admin";
    static final String[] PASSWORD_LIST = {
        "123456", "password", "admin123", "letmein", "qwerty",
        "football", "P@ssword1", "welcome1", "monkey123", "iloveyou"
    };

    static String attempt(String user, String pass) throws IOException {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(HOST, PORT), 3000);
            DataOutputStream out = new DataOutputStream(s.getOutputStream());
            writeString(out, user);
            writeString(out, pass);
            DataInputStream in = new DataInputStream(s.getInputStream());
            return in.readUTF();
        }
    }

    static void writeString(DataOutputStream out, String s) throws IOException {
        byte[] b = s.getBytes();
        out.writeShort(b.length);
        out.write(b);
    }

    public static void main(String[] args) throws Exception {
        System.out.println("=".repeat(62));
        System.out.println("   BRUTE-FORCE LOGIN ATTACK DETECTION AND PREVENTION SYSTEM  -  ATTACKER");
        System.out.println("=".repeat(62));
        System.out.printf("[*] Target user: '%s'  |  password list size: %d%n", USERNAME, PASSWORD_LIST.length);
        int i = 1;
        for (String pw : PASSWORD_LIST) {
            String result;
            try { result = attempt(USERNAME, pw); }
            catch (IOException e) { System.out.println("[X] Server not reachable"); return; }
            System.out.printf("[%02d] trying password '%s':  -> %s%n", i++, pw, result);
            if (result.equals("BLOCKED")) {
                System.out.println("[!] Attacker IP has been BLOCKED by the server - attack stopped");
                return;
            }
            Thread.sleep(300);
        }
        System.out.println("[*] Password list exhausted without success");
    }
}
