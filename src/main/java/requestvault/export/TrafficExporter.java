package requestvault.export;

import requestvault.model.TrafficRecord;

import java.io.File;
import java.io.IOException;
import java.util.List;

public interface TrafficExporter {
    String formatName();
    String fileExtension();
    ExportResult export(List<TrafficRecord> records, ExportOptions options, File destination) throws IOException;
}
