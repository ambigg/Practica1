
package Datos;

import java.io.*;
import java.nio.file.*;
import java.util.HashMap;
import java.util.Map;

import com.google.gson.Gson;

public class MetadataManager {

    private final String metadataPath;
    private final Gson gson = new Gson();

    public MetadataManager(String basePath) {
        this.metadataPath = basePath + "/metadata.json";
    }

    public void guardarMetadata(Map<String, Object> data) throws IOException {
        String json = gson.toJson(data);
        Files.writeString(Paths.get(metadataPath), json);
    }

    public Map<?, ?> leerMetadata() throws IOException {
        if (!Files.exists(Paths.get(metadataPath))) {
            return new HashMap<>();
        }
        String json = Files.readString(Paths.get(metadataPath));
        return gson.fromJson(json, Map.class);
    }
}