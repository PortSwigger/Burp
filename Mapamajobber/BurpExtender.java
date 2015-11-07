/*
 * Mapamajobber - Extract Burp proxy history to a file to illustrate all end points
 *
 * Write comma-delimited file with the following fields:
 *	Protocol
 *	Host
 *	Port
 *	Path
 *	Page
 *	Parameters - JSONified parameters; "Field" : "Value", ...
 *	Cookie - JSONified cookie-parameters
 * 
 * Aids with documentation for OTG-INFO-007: Map execution paths through application
 * and OTG-INFO-006: Identify application entry points
 *
 * Note that output file is hardcoded to /tmp/proxyHistory.csv
 * 
 * Next version will allow for filtering of exported filetypes
 */
package burp;

import java.io.BufferedWriter; // Output file writing
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter; // Error/output streams
import java.awt.Component;
import java.awt.Dimension; // Used to size button
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.swing.DefaultListModel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane; // UI panes^H^H^Hin
//import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JButton; // UI button
import javax.swing.SwingUtilities; // UI
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public class BurpExtender extends AbstractTableModel implements IBurpExtender,
		ITab, ActionListener {
	private static final long serialVersionUID = 1L;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JSplitPane splitPane;
	private final List<LogEntry> log = new ArrayList<LogEntry>();

	// Extender actions
	private String POPULATE = "0";
	private String WRITE = "1";

	public BufferedWriter outputFile;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		helpers = callbacks.getHelpers();

		// set our extension name
		callbacks.setExtensionName("Mapamajobber");

		// create our UI
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// Main split pane
				splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				splitPane.setOneTouchExpandable(true);
				splitPane.setDividerLocation(150);

				/* Create option interface in top pane */
				JPanel topPanel = new JPanel();

				// Run Button
				JButton btnRun = new JButton("Run");
				btnRun.addActionListener(BurpExtender.this);
				btnRun.setPreferredSize(new Dimension(125, 25));
				btnRun.setActionCommand(POPULATE);
				topPanel.add(btnRun);

				// Create file selection for output
				JButton btnWrite = new JButton("Write");
				btnWrite.addActionListener(BurpExtender.this);
				btnWrite.setPreferredSize(new Dimension(125, 25));
				btnWrite.setActionCommand(WRITE);
				topPanel.add(btnWrite);

				splitPane.setTopComponent(topPanel);

				/* Bottom Pane */

				// Create table of log entries in bottom pane
				Table logTable = new Table(BurpExtender.this);
				JScrollPane scrollPane = new JScrollPane(logTable);
				splitPane.setBottomComponent(scrollPane);

				// customize our UI components
				callbacks.customizeUiComponent(splitPane);
				callbacks.customizeUiComponent(logTable);
				callbacks.customizeUiComponent(scrollPane);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
			}
		});
	}

	//
	// implement ITab
	//
	@Override
	public String getTabCaption() {
		return "Mapamajobber";
	}

	@Override
	public Component getUiComponent() {
		return splitPane;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		callbacks.issueAlert("Performing action...");
		if (e.getActionCommand().equals(POPULATE)) {
			callbacks.issueAlert("Populating");
			populate();
		} else if (e.getActionCommand().equals(WRITE)) {
			callbacks.issueAlert("Exporting");
			writeFile();
		}

	}

	// Processes Proxy History and creates tables of in scope requests
	private void populate() {
		final boolean EXCLUDEVIEWSTATE = true;
		
		
		synchronized (log) {
			for (IHttpRequestResponse rr : callbacks.getProxyHistory()) {
				try {
					URL url = helpers.analyzeRequest(rr).getUrl();

					// Limit to in scope items
					if (callbacks.isInScope(url)) {
						// Build a list of parameters
						// TODO: Option for including values
						String parameters = "";
						String cookie = "";

						List<IParameter> params = helpers.analyzeRequest(rr)
								.getParameters();
						if (!params.isEmpty()) {
							for (IParameter param : params) {
								// Check if parameter is a cookie
								if (param.getType() == 2) {
									if (cookie.length() > 0) {
										cookie += "; ";
									}

									cookie += param.getName() + "=" + param.getValue();
								} else {
									if(!param.getName().matches(".*VIEWSTATE.*") || EXCLUDEVIEWSTATE == false){
										if (parameters.length() > 0) {
											parameters += "&";
										}
	
										parameters += param.getName() + "=" + param.getValue();
									}
								}

							}
						}

						if (cookie.length() > 0) {
							cookie = "\"" + cookie + "\"";
						}

						if (parameters.length() > 0) {
							parameters = "\"" + parameters + "\"";
						}

						IHttpService rrService = rr.getHttpService();

						String protocol = rrService.getProtocol();
						String host = rrService.getHost();
						int port = rrService.getPort();

						// Insert request to output log
						int row = log.size();
						log.add(new LogEntry(protocol, host, port, url,
								parameters, cookie));
						fireTableRowsInserted(row, row);
					}
				} catch (Exception x) {
					x.printStackTrace();
				}
			}
		}
	}

	// Output the Proxy History items to a comma-delimited file
	private void writeFile() {
		String record = "";
		//String qualifier = "\"";
		String qualifier = "";

		Set<LogEntry> recordSet = new HashSet<LogEntry>(log);

		try {
			File aFile = new File("/tmp/proxyHistory" + ".csv");
			outputFile = new BufferedWriter(new FileWriter(aFile,
					aFile.exists()));
		} catch (Exception catchX) {
			System.out.println("Output file error: " + catchX.getMessage());
			return;
		}

		// Output site map contents
		try {
			// Output header row
			outputFile.write("Protocol, Host, Port, Path, Page, Parameters, Cookie\n");

			for (LogEntry le : recordSet) {
				try {
					record = qualifier + le.protocol + qualifier + ", ";
					record += qualifier + le.host + qualifier +", ";
					record += "" + le.port + ", ";

					// Convert URL to path

					// Remove host
					String path = le.url.toString().replace(
							le.protocol + "://" + le.host + ":" + le.port, "");

					// Write the path
					record += qualifier + path.substring(0, path.lastIndexOf("/") + 1) + qualifier + ", ";

					// Write the page
					record += qualifier + path.substring(path.lastIndexOf("/") + 1) + qualifier + ", ";

					record += le.params + ", ";
					// record += le.cookie + "\n";

					outputFile.write(record);
					//recordSet.add(record);
					
					
				} catch (Exception x) {
					x.printStackTrace();
				}
			}
			
			// Write file
			//outputFile.write(recordSet);
//			Iterator<String> it = recordSet.iterator();
//			while(it.hasNext()) {
//			    outputFile.write(it.next() + "\n");
//			}
		} catch (Exception catchX) {
			System.out.println("Could not write to file: " + catchX.getMessage());
			return;
		}

		try {
			outputFile.close();
		} catch (Exception catchX) {
			System.out.println("Could not close file: " + catchX.getMessage());
			return;
		}

	}

	//
	// extend AbstractTableModel
	//

	@Override
	public int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 6;
	}

	@Override
	public String getColumnName(int columnIndex) {
		switch (columnIndex) {
		case 0:
			return "Protocol";
		case 1:
			return "Host";
		case 2:
			return "Port";
		case 3:
			return "URL";
		case 4:
			return "Parameters";
		case 5:
			return "Cookie";
		default:
			return "";
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		LogEntry logEntry = log.get(rowIndex);

		switch (columnIndex) {
		case 0:
			return logEntry.protocol;
		case 1:
			return logEntry.host;
		case 2:
			return logEntry.port;
		case 3:
			return logEntry.url.toString();
		case 4:
			return logEntry.params;
		case 5:
			return logEntry.cookie;
		default:
			return "";
		}
	}

	// extend JTable to handle cell selection
	private class Table extends JTable {
		public Table(TableModel tableModel) {
			super(tableModel);
		}
	}

	// class to hold details of each log entry
	private static class LogEntry {
		final String protocol;
		final String host;
		final int port;
		final URL url;
		final String params;
		final String cookie;

		LogEntry(String protocol, String host, int port, URL url,
				String params, String cookie) {
			this.protocol = protocol;
			this.host = host;
			this.port = port;
			this.url = url;
			this.params = params;
			this.cookie = cookie;
		}
	}
}
