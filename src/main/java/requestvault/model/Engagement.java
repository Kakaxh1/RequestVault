package requestvault.model;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class Engagement {

    private final String id;
    private String name;
    private String description;
    private final long createdAt;
    private final List<String> targetScope;

    public Engagement(String name) {
        this.id = UUID.randomUUID().toString();
        this.name = (name != null && !name.trim().isEmpty()) ? name : "Default Engagement";
        this.description = "";
        this.createdAt = System.currentTimeMillis();
        this.targetScope = new ArrayList<>();
    }

    public String getId() { return id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public long getCreatedAt() { return createdAt; }
    public List<String> getTargetScope() { return targetScope; }

    @Override
    public String toString() {
        return name;
    }
}
