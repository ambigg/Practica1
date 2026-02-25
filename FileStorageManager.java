
package Datos;

import java.io.*;
import java.nio.file.*;
import java.time.Instant;

public class FileStorageManager {

    private final String basePath;

    public FileStorageManager(String basePath) {
        this.basePath = basePath + "/archivos/";
        new File(this.basePath).mkdirs();
    }

    public void crearArchivo(String nombre, String contenido) throws IOException {
        Path path = Paths.get(basePath + nombre);
        Files.write(path, contenido.getBytes());
    }

    public String leerArchivo(String nombre) throws IOException {
        Path path = Paths.get(basePath + nombre);
        return Files.readString(path);
    }

    public void escribirArchivo(String nombre, String contenido) throws IOException {
        Path path = Paths.get(basePath + nombre);
        Files.write(path, contenido.getBytes(), StandardOpenOption.TRUNCATE_EXISTING);
    }

    public void eliminarArchivo(String nombre) throws IOException {
        Files.deleteIfExists(Paths.get(basePath + nombre));
    }

    public long obtenerUltimaModificacion(String nombre) throws IOException {
        return Files.getLastModifiedTime(Paths.get(basePath + nombre)).toMillis();
    }
}
