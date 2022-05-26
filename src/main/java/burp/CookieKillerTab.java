package burp;

import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.text.Position;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Vector;

public class CookieKillerTab {
    private JList cookieList;
    private JTextField cookieField;
    private JLabel titleLabel;
    private JPanel rootPanel;
    private JButton addButton;
    private JButton jarfillButton;
    private JButton deleteButton;
    private DefaultListModel<String> cookieModel;

    private IBurpExtenderCallbacks callbacks;

    public void saveSettings() {
        callbacks.saveExtensionSetting("cookies", String.join("; ", getCookies()));
    }

    public void loadSettings() {
        String cookies = callbacks.loadExtensionSetting("cookies");
        cookieModel = new DefaultListModel();
        if (cookies == null) {
            cookieList.setModel(cookieModel);
            return;
        }

        String[] cookieArray = cookies.split("; {0,1}");
        for (String s : cookieArray) {
            cookieModel.addElement(s);
        }
        cookieList.setModel(cookieModel);
    }

    public String[] getCookies() {
        Object[] objectArr = cookieModel.toArray();
        String[] cookies = new String[objectArr.length];
        for (int i = 0; i < cookies.length; i++) {
            cookies[i] = objectArr[i].toString();
        }
        return cookies;
    }

    public void printException(Exception e) {
        callbacks.printOutput(e.toString());
        callbacks.printOutput(e.getMessage());
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        e.printStackTrace(pw);
        callbacks.printOutput(sw.toString());
    }

    public int listModelStringSearch(DefaultListModel m, String value) {
        for (int i = 0; i < m.size(); i++) {
            if (m.get(i).toString().equals(value)) {
                return i;
            }
        }

        // string not found
        return -1;
    }

    public CookieKillerTab(IBurpExtenderCallbacks callbacks) {
        try {
            this.callbacks = callbacks;
            loadSettings();
        } catch (Exception x) {
            printException(x);
        }

        // Fill With Cookie Jar listener
        jarfillButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                java.util.List<ICookie> cookies = callbacks.getCookieJarContents();
                for (int i = 0; i < cookies.size(); i++) {
                    cookieModel.addElement(cookies.get(i).getName());
                }
                saveSettings();
            }
        });

        // list selection listener
        cookieList.addListSelectionListener(new ListSelectionListener() {
            @Override
            public void valueChanged(ListSelectionEvent e) {
                cookieField.setText((String) cookieList.getSelectedValue());
            }
        });

        // add button listener
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    // get string from cookieField
                    String value = cookieField.getText();

                    // getNextMatch doesn't work
                    //int index = cookieList.getNextMatch(value, 0, Position.Bias.Forward);

                    // search JList
                    int index = listModelStringSearch(cookieModel, value);
                    // if string is found, return
                    if (index != -1) {
                        return;
                    }

                    // add element to listmodel in jlist
                    cookieModel.addElement(value);
                    saveSettings();

                } catch (Exception x) {
                    printException(x);
                }
            }
        });

        // delete button listener
        deleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                try {
                    int saveSelect = cookieList.getSelectedIndex();
                    int index = cookieList.getSelectedIndices().length - 1;
                    while (cookieList.getSelectedIndices().length != 0) {
                        cookieModel.removeElementAt(cookieList.getSelectedIndices()[index--]);
                    }

                    // set selected index
                    cookieList.setSelectedIndex(saveSelect);
                    saveSettings();

                } catch (Exception x) {
                    printException(x);
                }
            }
        });
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        rootPanel = new JPanel();
        rootPanel.setLayout(new GridLayoutManager(3, 3, new Insets(0, 0, 0, 0), -1, -1));
        titleLabel = new JLabel();
        Font titleLabelFont = this.$$$getFont$$$(null, -1, 20, titleLabel.getFont());
        if (titleLabelFont != null) titleLabel.setFont(titleLabelFont);
        titleLabel.setText("CookieKiller");
        rootPanel.add(titleLabel, new GridConstraints(0, 0, 1, 2, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_NONE, GridConstraints.SIZEPOLICY_FIXED, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        cookieField = new JTextField();
        cookieField.setToolTipText("Regex String (Matching whole cookie name)");
        rootPanel.add(cookieField, new GridConstraints(1, 0, 1, 1, GridConstraints.ANCHOR_WEST, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        addButton = new JButton();
        addButton.setText("Add");
        rootPanel.add(addButton, new GridConstraints(1, 1, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        jarfillButton = new JButton();
        jarfillButton.setText("Fill With Cookie Jar");
        rootPanel.add(jarfillButton, new GridConstraints(0, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        deleteButton = new JButton();
        deleteButton.setText("Delete");
        rootPanel.add(deleteButton, new GridConstraints(1, 2, 1, 1, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_HORIZONTAL, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_CAN_GROW, GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JScrollPane scrollPane1 = new JScrollPane();
        rootPanel.add(scrollPane1, new GridConstraints(2, 0, 1, 3, GridConstraints.ANCHOR_CENTER, GridConstraints.FILL_BOTH, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, GridConstraints.SIZEPOLICY_CAN_SHRINK | GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        cookieList = new JList();
        cookieList.setSelectionMode(1);
        scrollPane1.setViewportView(cookieList);
    }

    /**
     * @noinspection ALL
     */
    private Font $$$getFont$$$(String fontName, int style, int size, Font currentFont) {
        if (currentFont == null) return null;
        String resultName;
        if (fontName == null) {
            resultName = currentFont.getName();
        } else {
            Font testFont = new Font(fontName, Font.PLAIN, 10);
            if (testFont.canDisplay('a') && testFont.canDisplay('1')) {
                resultName = fontName;
            } else {
                resultName = currentFont.getName();
            }
        }
        return new Font(resultName, style >= 0 ? style : currentFont.getStyle(), size >= 0 ? size : currentFont.getSize());
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return rootPanel;
    }

}
