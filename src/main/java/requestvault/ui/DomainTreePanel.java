package requestvault.ui;

import requestvault.model.TrafficRecord;
import requestvault.storage.TrafficStore;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.tree.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

public class DomainTreePanel extends JPanel {

    public interface DomainSelectionListener {
        void onDomainSelectionChanged(Set<String> selectedHosts);
    }

    public static class CheckTreeNode extends DefaultMutableTreeNode {
        private final String hostName;
        private boolean isSelected;
        private final boolean isRoot;

        public CheckTreeNode(String hostName, boolean isSelected, boolean isRoot) {
            super(hostName);
            this.hostName = hostName;
            this.isSelected = isSelected;
            this.isRoot = isRoot;
        }

        public String getHostName() { return hostName; }
        public boolean isSelected() { return isSelected; }
        public void setSelected(boolean selected) { this.isSelected = selected; }
        public boolean isRoot() { return isRoot; }
    }

    private final TrafficStore store;
    private final DomainSelectionListener listener;
    private final JTextField searchField;
    private final JTree tree;
    private final DefaultTreeModel treeModel;
    private final CheckTreeNode rootNode;
    private final Set<String> selectedHosts = new HashSet<>();
    private final Map<String, Set<String>> domainMap = new TreeMap<>();

    public DomainTreePanel(TrafficStore store, DomainSelectionListener listener) {
        this.store = store;
        this.listener = listener;

        setLayout(new BorderLayout(4, 4));
        setBorder(BorderFactory.createTitledBorder("Domain / Subdomain Filter"));

        // Top Search
        JPanel searchPanel = new JPanel(new BorderLayout(4, 4));
        searchPanel.setBorder(BorderFactory.createEmptyBorder(2, 4, 4, 4));
        searchPanel.add(new JLabel("Search:"), BorderLayout.WEST);
        searchField = new JTextField();
        searchPanel.add(searchField, BorderLayout.CENTER);
        add(searchPanel, BorderLayout.NORTH);

        // Center Checkbox Tree
        rootNode = new CheckTreeNode("All Domains", true, true);
        treeModel = new DefaultTreeModel(rootNode);
        tree = new JTree(treeModel);
        tree.setRootVisible(false);
        tree.setShowsRootHandles(true);
        tree.setCellRenderer(new CheckTreeCellRenderer());

        // Mouse click on checkbox toggles selection
        tree.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                TreePath path = tree.getPathForLocation(e.getX(), e.getY());
                if (path != null) {
                    Object last = path.getLastPathComponent();
                    if (last instanceof CheckTreeNode) {
                        CheckTreeNode node = (CheckTreeNode) last;
                        boolean newState = !node.isSelected();
                        toggleNode(node, newState);
                        treeModel.nodeChanged(node);
                        tree.repaint();
                        notifyListener();
                    }
                }
            }
        });

        JScrollPane scrollPane = new JScrollPane(tree);
        scrollPane.setPreferredSize(new Dimension(240, 220));
        add(scrollPane, BorderLayout.CENTER);

        // Bottom Action Buttons
        JPanel bottomPanel = new JPanel(new GridLayout(1, 3, 4, 4));
        bottomPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

        JButton selectAllBtn = new JButton("Select All");
        selectAllBtn.setFont(selectAllBtn.getFont().deriveFont(11f));
        selectAllBtn.addActionListener(e -> {
            setAllSelected(true);
            notifyListener();
        });

        JButton deselectAllBtn = new JButton("Deselect All");
        deselectAllBtn.setFont(deselectAllBtn.getFont().deriveFont(11f));
        deselectAllBtn.addActionListener(e -> {
            setAllSelected(false);
            notifyListener();
        });

        JButton refreshBtn = new JButton("↻ Refresh");
        refreshBtn.setFont(refreshBtn.getFont().deriveFont(11f));
        refreshBtn.addActionListener(e -> refreshDomains());

        bottomPanel.add(selectAllBtn);
        bottomPanel.add(deselectAllBtn);
        bottomPanel.add(refreshBtn);
        add(bottomPanel, BorderLayout.SOUTH);

        searchField.getDocument().addDocumentListener(new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { rebuildTree(); }
            public void removeUpdate(DocumentEvent e) { rebuildTree(); }
            public void changedUpdate(DocumentEvent e) { rebuildTree(); }
        });

        refreshDomains();
    }

    public Set<String> getSelectedHosts() {
        return new HashSet<>(selectedHosts);
    }

    public void refreshDomains() {
        List<TrafficRecord> records = store.getAllRecords();
        domainMap.clear();

        for (TrafficRecord r : records) {
            String host = r.getHost();
            if (host != null && !host.trim().isEmpty()) {
                host = host.toLowerCase(Locale.ROOT);
                String parentDomain = extractParentDomain(host);
                domainMap.computeIfAbsent(parentDomain, k -> new TreeSet<>()).add(host);
                selectedHosts.add(host);
            }
        }
        rebuildTree();
    }

    private void rebuildTree() {
        rootNode.removeAllChildren();
        String filter = searchField.getText().trim().toLowerCase(Locale.ROOT);

        for (Map.Entry<String, Set<String>> entry : domainMap.entrySet()) {
            String parent = entry.getKey();
            Set<String> subdomains = entry.getValue();

            boolean parentMatches = filter.isEmpty() || parent.contains(filter);
            boolean anyChildMatches = false;
            for (String sub : subdomains) {
                if (filter.isEmpty() || sub.contains(filter)) {
                    anyChildMatches = true;
                    break;
                }
            }

            if (parentMatches || anyChildMatches) {
                boolean parentChecked = subdomains.stream().anyMatch(selectedHosts::contains);
                CheckTreeNode parentNode = new CheckTreeNode(parent, parentChecked, false);

                for (String sub : subdomains) {
                    if (filter.isEmpty() || sub.contains(filter) || parentMatches) {
                        CheckTreeNode childNode = new CheckTreeNode(sub, selectedHosts.contains(sub), false);
                        parentNode.add(childNode);
                    }
                }
                rootNode.add(parentNode);
            }
        }

        treeModel.reload();
        for (int i = 0; i < tree.getRowCount(); i++) {
            tree.expandRow(i);
        }
    }

    private void toggleNode(CheckTreeNode node, boolean selected) {
        node.setSelected(selected);
        if (node.getChildCount() > 0) {
            for (int i = 0; i < node.getChildCount(); i++) {
                CheckTreeNode child = (CheckTreeNode) node.getChildAt(i);
                child.setSelected(selected);
                if (selected) {
                    selectedHosts.add(child.getHostName());
                } else {
                    selectedHosts.remove(child.getHostName());
                }
            }
        } else {
            if (selected) {
                selectedHosts.add(node.getHostName());
            } else {
                selectedHosts.remove(node.getHostName());
            }
            if (node.getParent() instanceof CheckTreeNode) {
                CheckTreeNode parent = (CheckTreeNode) node.getParent();
                boolean anySelected = false;
                for (int i = 0; i < parent.getChildCount(); i++) {
                    if (((CheckTreeNode) parent.getChildAt(i)).isSelected()) {
                        anySelected = true;
                        break;
                    }
                }
                parent.setSelected(anySelected);
                treeModel.nodeChanged(parent);
            }
        }
    }

    private void setAllSelected(boolean selected) {
        for (Set<String> subs : domainMap.values()) {
            if (selected) {
                selectedHosts.addAll(subs);
            } else {
                selectedHosts.removeAll(subs);
            }
        }
        setNodeSelectedRecursive(rootNode, selected);
        treeModel.nodeChanged(rootNode);
        tree.repaint();
    }

    private void setNodeSelectedRecursive(CheckTreeNode node, boolean selected) {
        node.setSelected(selected);
        for (int i = 0; i < node.getChildCount(); i++) {
            setNodeSelectedRecursive((CheckTreeNode) node.getChildAt(i), selected);
        }
    }

    private void notifyListener() {
        if (listener != null) {
            listener.onDomainSelectionChanged(getSelectedHosts());
        }
    }

    private String extractParentDomain(String host) {
        if (host == null) return "";
        String[] parts = host.split("\\.");
        if (parts.length >= 2) {
            return parts[parts.length - 2] + "." + parts[parts.length - 1];
        }
        return host;
    }

    // Tree Cell Renderer with Checkbox
    private static class CheckTreeCellRenderer extends JPanel implements TreeCellRenderer {
        private final JCheckBox checkBox = new JCheckBox();
        private final JLabel label = new JLabel();

        public CheckTreeCellRenderer() {
            setLayout(new FlowLayout(FlowLayout.LEFT, 4, 1));
            setOpaque(false);
            checkBox.setOpaque(false);
            add(checkBox);
            add(label);
        }

        @Override
        public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected, boolean expanded, boolean leaf, int row, boolean hasFocus) {
            if (value instanceof CheckTreeNode) {
                CheckTreeNode node = (CheckTreeNode) value;
                checkBox.setSelected(node.isSelected());
                label.setText(node.getHostName());
                if (!leaf) {
                    label.setFont(label.getFont().deriveFont(Font.BOLD));
                } else {
                    label.setFont(label.getFont().deriveFont(Font.PLAIN));
                }
            }
            return this;
        }
    }
}
