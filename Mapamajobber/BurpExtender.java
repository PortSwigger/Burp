/*****************************************************************************
 * Mapamajobber - Extract Burp's Proxy History tab contents to a file to 
 * 		illustrate all end points
 * 
 * Aids with documentation of OWASP Testing Guide V4 tests OTG-INFO-007: Map 
 * execution paths through application and OTG-INFO-006: Identify application 
 * entry points
 *
 * Write comma-delimited file with the following fields:
 *	Protocol - Text protocol (http/https)
 *	Host - Domain name of site
 *	Port
 *	Path
 *	Page - Requested resource
 *  Query String
 *	Parameters - URL, ampersand-delimited field/value pairs
 *	Cookie - Semi-colon delimited field/value pairs
 */
package burp;

import java.io.BufferedWriter; // Output file writing
import java.io.File;
import java.io.FileWriter;
//import java.io.PrintWriter; // Error/output streams
import java.awt.Component;
import java.awt.Dimension; // Used to size button
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
//import javax.swing.DefaultListModel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane; // UI panes^H^H^Hin
//import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JButton; // UI button
import javax.swing.SwingUtilities; // UI
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import javax.swing.JFileChooser;

public class BurpExtender extends AbstractTableModel implements IBurpExtender,
		ITab, ActionListener {
	private static final long serialVersionUID = 1L;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private JSplitPane splitPane;
	
	// Options to control file contents
	private static JCheckBox optScope = new JCheckBox("In scope only", true);
	private static JCheckBox optUnique = new JCheckBox("Unique results");
	private static JCheckBox optIncludeParam = new JCheckBox("Include parameters", true);
	private static JCheckBox optIncludeViewstate = new JCheckBox("Include VIEWSTATE parameters (.NET)", false);
	private static JCheckBox optIncludeCookie = new JCheckBox("Include cookies", true);
	
	// Log entry listing
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

		// Create our lame UI (Swing is too horrible to figure out) 
		SwingUtilities.invokeLater(new Runnable() {
			@Override
			public void run() {
				// Main split pane
				splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				splitPane.setOneTouchExpandable(true);
				splitPane.setDividerLocation(150);

				/* Create option interface in top pane */
				JPanel topPanel = new JPanel();

				topPanel.add(optScope);
				topPanel.add(optUnique);
				topPanel.add(optIncludeParam);
				topPanel.add(optIncludeViewstate);
				topPanel.add(optIncludeCookie);
				
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
		if (e.getActionCommand().equals(POPULATE)) {
			populate();
		} else if (e.getActionCommand().equals(WRITE)) {
			writeFile();
		}
	}

	// Processes Proxy History and creates table of in scope requests
	private void populate() {
		String parameters = "";
		String cookie = "";
		
		synchronized (log) {
			log.clear();
			
			for (IHttpRequestResponse rr : callbacks.getProxyHistory()) {
				try {
					URL url = helpers.analyzeRequest(rr).getUrl();

					// Limit to in scope items
					if (callbacks.isInScope(url) || !optScope.isSelected()) {
						// Build a list of parameters
						if(optIncludeParam.isSelected() || optIncludeCookie.isSelected()) {
							parameters = "";
							cookie = "";
							
							// TODO: Option for including values
							List<IParameter> params = helpers.analyzeRequest(rr)
									.getParameters();
							if (!params.isEmpty()) {
								for (IParameter param : params) {
									// Check if parameter is a cookie
									if (param.getType() == 2 && optIncludeCookie.isSelected()) {
										if (cookie.length() > 0) {
											cookie += "; ";
										}
	
										cookie += param.getName() + "=" + param.getValue();
									} else if(optIncludeParam.isSelected()) {
										// Include parameters, evaluating 
										// for VIEWSTATE setting
										if (optIncludeViewstate.isSelected()
												|| !param.getName().matches(".*VIEWSTATE.*")) {
											if (parameters.length() > 0) {
												parameters += "&";
											}
		
											parameters += param.getName() + "=" + param.getValue();
										}
									}
	
								}
							}
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
		String queryString = "";

		// Check for log
		if(log.size() == 0) {
			populate();
		}
		
		// Get unique set of proxy records to write
		Set<LogEntry> recordSet = new HashSet<LogEntry>(log);

		try {
			// Select file
			File fileHandle = getFilename("Mapamajobber");

			outputFile = new BufferedWriter(new FileWriter(fileHandle));
		} catch (Exception catchX) {
			if(catchX.getMessage() != null) {
				System.out.println("Output file error: " + catchX.getMessage());
			}
			
			return;
		}

		// Output site map contents
		try {
			// Output header row
			outputFile.write("Protocol, Host, Port, Path, Page, QueryString, Parameters, Cookie\n");

			for (LogEntry le : recordSet) {
				try {
					record = le.protocol + ", ";
					record += le.host + ", ";
					record += "" + le.port + ", ";

					// Convert URL to path

					// Remove host
					String path = le.url.toString().replace(
							le.protocol + "://" + le.host + ":" + le.port, "");

					// Check for query string as it impacts path/page handling
					if(path.contains("?")) {
						queryString = path.substring(path.lastIndexOf("?") + 1);
						
						// Strip query string from path, since it may 
						// contain a slash
						path = path.substring(0, path.indexOf("?"));
						
					} else {
						queryString = "";
					}

					// Path; excludes page/query string
					record += path.substring(0, path.lastIndexOf("/") + 1) + ", ";

					// Page; excludes the path and query string
					record += path.substring(path.lastIndexOf("/") + 1) + ", ";
					
					// Query string
					record += queryString + ", ";
					
					record += le.params + ", ";
					record += le.cookie + "\n";

					outputFile.write(record);
				} catch (Exception x) {
					x.printStackTrace();
				}
			}
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

	// Get file handle to write to
	private File getFilename(String filename) {
		File handle = null;
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Comma-delimited text (CSV)", "csv");
		JFileChooser chooser = null;
		
		if(chooser == null) {
			chooser = new JFileChooser();
			chooser.setDialogTitle("Export Proxy History");
			chooser.setFileFilter(filter);
			chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
			chooser.setSelectedFile(new File(filename + ".csv"));
			chooser.setAcceptAllFileFilterUsed(false);                      
		}

		int val = chooser.showSaveDialog((Component)null);

		if(val == JFileChooser.APPROVE_OPTION) {
			handle = chooser.getSelectedFile();
		}

		if(handle.exists()) {
			int result = JOptionPane.showConfirmDialog(null,"The file exists, overwrite?","Existing file",JOptionPane.YES_NO_CANCEL_OPTION);
            switch(result){
                case JOptionPane.NO_OPTION:
                    handle = getFilename("Mapamajobber");
                case JOptionPane.CLOSED_OPTION:
                    handle = null;
                case JOptionPane.CANCEL_OPTION:
                    handle = null;
            }			
		}
			
		return handle;
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

	// Extend JTable to handle cell selection
	private class Table extends JTable {
		private static final long serialVersionUID = 3924318623855753102L;

		public Table(TableModel tableModel) {
			super(tableModel);
		}
	}

	// Log Entry record structure
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

		// Used to determine what constitutes a unique record
		@Override
		public boolean equals(Object compare) {
			LogEntry obj = (LogEntry)compare;

			// TODO: Options to determine unique records
			if(optUnique.isSelected()) {
				if(url.equals(obj.url)) {
					return true;
				}
			} else if(url.equals(obj.url)
					&& params.equals(obj.params) 
					&& cookie.equals(obj.cookie)
					) {
				return true;
			}

			return false;
		}
		
		@Override
		public int hashCode() {
			return (url).hashCode(); 
		}
	}
}
