
package Datos;

import java.io.*;
import java.nio.file.*;

public class TempRepositoryManager {

    private final String tempPath;

    public TempRepositoryManager(String basePath) {
        this.tempPath = basePath + "/temporales/";
        new File(this.tempPath).mkdirs();
    }

    public void guardarCopia(String nombre, String contenido) throws IOException {
        Files.write(Paths.get(tempPath + nombre), contenido.getBytes());
    }

    public String leerCopia(String nombre) throws IOException {
        return Files.readString(Paths.get(tempPath + nombre));
    }

    public void eliminarCopia(String nombre) throws IOException {
        Files.deleteIfExists(Paths.get(tempPath + nombre));
    }
}