/*****************************************************************************
 * MindMap Explorter  - Extract Burp's Proxy History tab contents to a 
 * 	comma-delimited and/or Mindamap files in order to illustrate all end
 * 	points
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
 *
 * Generates a Mindmap (Freemind.sourceforge.net). Note that layout is very
 * generic and can be immediately improved by opening in Freemind, selecting
 * root node and using Tools/Sort Children
 */
package burp;

import java.io.BufferedWriter; // Output file writing
import java.io.File;
import java.io.FileWriter;
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
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane; // UI panes^H^H^Hin
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
	private static JCheckBox optUnique = new JCheckBox("Unique results", false);
	private static JCheckBox optExclude404 = new JCheckBox("Exclude 404's", true);
	private static JCheckBox optIncludeParam = new JCheckBox("Include parameters", true);
	private static JCheckBox optIncludeViewstate = new JCheckBox("Include VIEWSTATE parameters (.NET)", false);
	private static JCheckBox optIncludeCookie = new JCheckBox("Include cookies", true);
	private static JCheckBox optOutputFile = new JCheckBox("Output Proxy log (CSV)", true);
	private static JCheckBox optOutputMindmap = new JCheckBox("Output Mindmap", true);
	
	// Log entry listing
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	
	// Mindmap Node list
	private final List<XmlNode> node = new ArrayList<XmlNode>();

	// Extender actions (using these as boolean operations, 
	// but setActionCommand needs strings, apparently)
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
		callbacks.setExtensionName("MindMap Exporter");

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
				topPanel.add(optExclude404);
				topPanel.add(optIncludeParam);
				topPanel.add(optIncludeViewstate);
				topPanel.add(optIncludeCookie);
				topPanel.add(optOutputFile);
				topPanel.add(optOutputMindmap);
				
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

	// Implement ITab
	@Override
	public String getTabCaption() {
		return "MindMap Exporter";
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
			// Check for log
			if(log.size() == 0) {
				populate();
			}
			
			if(optOutputFile.isSelected()) {
				writeFile();
			}
			
			if(optOutputMindmap.isSelected()) {
				writeMindmap();
			}
		}
	}

	// Processes Proxy History and creates table of in scope requests
	private void populate() {
		String parameters = "";
		String cookie = "";
		URL url;
		byte[] response;		// Used to check status code
		
		synchronized (log) {
			log.clear();
			
			for (IHttpRequestResponse rr : callbacks.getProxyHistory()) {
				try {
					url = helpers.analyzeRequest(rr).getUrl();
					
					// If there is no response or we are excluding 404's, skip entry
					response = rr.getResponse();
					if (response == null
							|| (optExclude404.isSelected() && helpers
									.analyzeResponse(response).getStatusCode() == 404)) {
						continue;
					}

					// Limit to in scope items
					if (callbacks.isInScope(url) || !optScope.isSelected()) {
						// Build a list of parameters
						if(optIncludeParam.isSelected() || optIncludeCookie.isSelected()) {
							parameters = "";
							cookie = "";
							
							// TODO: Option for including values?
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

		// Get unique set of proxy records to write
		Set<LogEntry> recordSet = new HashSet<LogEntry>(log);

		try {
			// Select file
			File fileHandle = getFilename("MindMap Exporter", "csv");

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

	private void writeMindmap() {
		// Use path and pages to create map
		String xmlMap = "<map version=\"1.0.1\">";
		String xmlNodes = "";
		String fqdn = "";
		
		Integer xmlId;
		int xmlParent = 0;
		int newId = 1;
		
		String[] resources;
		
		// To handle multiple sites, we need to determine the FQDN, which
		// will be used as the root node.
		for (LogEntry le : log) {
			if(fqdn == "") {
				fqdn = le.host;
			}
			
			// Find occurrence of different hosts
			if(fqdn != le.host && !fqdn.equals("0.0.0.0")) {
				// Check if it is an IP address
				if(le.host.replaceAll("[0-9\\.]", "").length() == 0) {
					// Multiple IP addresses; use 0.0.0.0
					fqdn = "0.0.0.0";
				} else {
					int x;
					int y;
					
					// Run backwards through the hosts to identify the first difference
					x = fqdn.length() - 1;
					y = le.host.length() - 1;
					
					while(fqdn.charAt(x) == le.host.charAt(y) && x >= 0 && y >= 0) {
						// System.out.println("Match " + x + "/" +y);
						if(x == 0 || y == 0) {
							break;
						}
						
						x--;
						y--;					
					}
					
					// Assume the like parts are the FQDN or that the first
					// result was the FQDN, so there is no change
					if(fqdn.substring(x).equalsIgnoreCase(le.host.substring(y))) {
						fqdn = fqdn.substring(x);
						break;
					}
				}
			}
		}
		
		// Add FQDN as root node >> node.add(new XmlNode(0, fqdn, 0));
		// This is hard-coded to reduce recursion necessary to process the nodes
		// which was throwing a stack overflow
		xmlMap += "<node ID=\"ID_" + 0 + "\" TEXT=\"" + fqdn + "\">";

		for (LogEntry le : log) {
			try {
				// Remove host
				String path = le.url.toString().replace(
						le.protocol + "://" + le.host + ":" + le.port, "");

				// Check for query string as it impacts path/page handling
				if(path.contains("?")) {
					// Strip query string from path, since it may 
					// contain a slash
					path = path.substring(0, path.indexOf("?"));
				}
				
				// Clear the leading slash
				if(path.startsWith("/")) {
					path = path.substring(1);
				}

				// Check for a different sub-domain and prepend to path
				if(!le.host.equals(fqdn)) {
					
					if(fqdn.equals("0.0.0.0")) {
						// Assuming IP address; prepend
						path = le.host + "/" + path;
					} else {
						// Remove FQDN:
						// 	Length of subdomain = [host length] - [FQDN length] - 'period'					
						path = le.host.substring(0, (le.host.length() - fqdn.length()) - 1) + "/" + path;
					}
				}
				
				// Use directories and pages as a list of resources
				resources = path.split("/");
				
				// Cycle through resources to determine unique parent/child occurrences
				for(int i = 0; i < resources.length; i++) {
					xmlId = null;
					
					// First resource, point back to root
					if(i == 0) {
						xmlParent = 0;
					}
					
					// Search for existing node
					for(XmlNode resource : node) {
						if(resources[i].equals(resource.Text) && resource.Parent == xmlParent) {
							xmlId = resource.Id;
							break;
						}
					}
					
					// New node, add it
					if(xmlId == null) {
						xmlId = newId++;
						node.add(new XmlNode(xmlId, resources[i], xmlParent));
					}
					
					// Store Id as Parent for next resource
					xmlParent = xmlId;
				}
			} catch (Exception x) {
				x.printStackTrace();
			}
		}
		
		try {
			// Select file
			File fileHandle = getFilename("MindMap Exporter", "mm");

			outputFile = new BufferedWriter(new FileWriter(fileHandle));
		} catch (Exception catchX) {
			if(catchX.getMessage() != null) {
				System.out.println("Output file error: " + catchX.getMessage());
			}
			
			return;
		}
		
		// Output Mindmap nodes
		try {
			// Loop through resources
			for (XmlNode xn : node) {
				try {
					// Use base resources to determine all children
					if(xn.Parent == 0) {
						xmlNodes += makeNode(xn.Id);
					}
					
				} catch (Exception x) {
					x.printStackTrace();
				}
			}
			
			// Compile output and write it
			xmlMap += xmlNodes + "</node></map>";
			outputFile.write(xmlMap);
			
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
	private File getFilename(String filename, String extension) {
		File handle = null;
		FileNameExtensionFilter filter;
		
		switch(extension) {
			case "mm":
				filter = new FileNameExtensionFilter("Mindmap", "mm");
			default:
				filter = new FileNameExtensionFilter("Comma-delimited text (CSV)", "csv");
		}
		
		JFileChooser chooser = null;
		
		if(chooser == null) {
			chooser = new JFileChooser();
			chooser.setDialogTitle("Export Proxy History");
			chooser.setFileFilter(filter);
			chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
			chooser.setSelectedFile(new File(filename + "." + extension));
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
                    handle = getFilename("MindMap Exporter", extension);
                case JOptionPane.CLOSED_OPTION:
                    handle = null;
                case JOptionPane.CANCEL_OPTION:
                    handle = null;
            }			
		}
			
		return handle;
	}
	
	
	// Extend AbstractTableModel
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
	
	// Retrieve node details and call recursively to determine child nodes
	private String makeNode(int Id) {
		String nodeText = "";
		String childText = "";
		// TODO: Modify nodes to contain formatting attributes
		
		for(XmlNode xn : node) {
			if(xn.Id == Id) {
				// Mindmap node format: <node ID="ID_$x" TEXT="$name"></node>
				nodeText += "<node ID=\"ID_" + Id + "\" TEXT=\"" + xn.Text + "\">";
				
				// Find all child nodes
				for(XmlNode child : node) {
					if(child.Parent == xn.Id) {
						childText = makeNode(child.Id);
						
						// Check if there are no more children
						if(childText == "") {
							break;
						} else {
							nodeText += childText;
							childText = "";
						}
					}
				}
				
				nodeText += "</node>";
			}
		}
		
		return nodeText;
	}
	
	private static class XmlNode {
		final int Id;
		final String Text;
		final int Parent;
		
		XmlNode(int Id, String Text, int Parent) {
			this.Id = Id;
			this.Text = Text;
			this.Parent = Parent;
		}
		
//		public int find(String Text, int Parent) {
//			for(XmlNode resource : node) {
//				if(resource.Parent == Parent && resource.Text == Text) {
//					return resource.Id;
//				}
//			}
//			
//			return -1;
//		}
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
