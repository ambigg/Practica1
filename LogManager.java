
package Datos;


import java.io.*;
import java.time.LocalDateTime;

public class LogManager {

    private final String logPath;

    public LogManager(String basePath) {
        this.logPath = basePath + "/logs/log.txt";
        new File(basePath + "/logs/").mkdirs();
    }

    public synchronized void escribirLog(String mensaje) {
        try (FileWriter fw = new FileWriter(logPath, true);
             BufferedWriter bw = new BufferedWriter(fw)) {

            bw.write(LocalDateTime.now() + " - " + mensaje);
            bw.newLine();

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}