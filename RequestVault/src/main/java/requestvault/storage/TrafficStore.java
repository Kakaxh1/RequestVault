package requestvault.storage;

import requestvault.model.Engagement;
import requestvault.model.TrafficRecord;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

public class TrafficStore {

    public interface StoreListener {
        void onRecordsChanged();
    }

    private final List<TrafficRecord> records = new CopyOnWriteArrayList<>();
    private final Set<String> requestHashes = Collections.synchronizedSet(new HashSet<>());
    private final List<Engagement> engagements = new CopyOnWriteArrayList<>();
    private final List<StoreListener> listeners = new CopyOnWriteArrayList<>();
    private Engagement currentEngagement;

    public TrafficStore() {
        Engagement def = new Engagement("Engagement - " + java.time.LocalDate.now());
        engagements.add(def);
        currentEngagement = def;
    }

    public void addListener(StoreListener listener) {
        listeners.add(listener);
    }

    public void removeListener(StoreListener listener) {
        listeners.remove(listener);
    }

    private void notifyListeners() {
        for (StoreListener l : listeners) {
            try {
                l.onRecordsChanged();
            } catch (Exception ignored) {}
        }
    }

    public synchronized boolean addRecord(TrafficRecord record, boolean deduplicate) {
        if (record == null) return false;
        
        if (deduplicate) {
            String hash = record.getRequestHash();
            if (requestHashes.contains(hash)) {
                return false;
            }
            requestHashes.add(hash);
        }

        if (record.getEngagementId() == null && currentEngagement != null) {
            record.setEngagementId(currentEngagement.getId());
        }

        record.setSequenceNumber(records.size() + 1);
        records.add(record);
        notifyListeners();
        return true;
    }

    public synchronized int addRecords(List<TrafficRecord> newRecords, boolean deduplicate) {
        int added = 0;
        for (TrafficRecord r : newRecords) {
            if (deduplicate) {
                String hash = r.getRequestHash();
                if (requestHashes.contains(hash)) {
                    continue;
                }
                requestHashes.add(hash);
            }
            if (r.getEngagementId() == null && currentEngagement != null) {
                r.setEngagementId(currentEngagement.getId());
            }
            r.setSequenceNumber(records.size() + 1);
            records.add(r);
            added++;
        }
        if (added > 0) {
            notifyListeners();
        }
        return added;
    }

    public List<TrafficRecord> getAllRecords() {
        return new ArrayList<>(records);
    }

    public synchronized void clear() {
        records.clear();
        requestHashes.clear();
        notifyListeners();
    }

    public int size() {
        return records.size();
    }

    public Engagement getCurrentEngagement() {
        return currentEngagement;
    }

    public void setCurrentEngagement(Engagement engagement) {
        this.currentEngagement = engagement;
        notifyListeners();
    }

    public List<Engagement> getEngagements() {
        return new ArrayList<>(engagements);
    }

    public void addEngagement(Engagement engagement) {
        engagements.add(engagement);
        this.currentEngagement = engagement;
        notifyListeners();
    }
}
