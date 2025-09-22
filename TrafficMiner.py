# -*- coding: utf-8 -*-
# TrafficMiner - Burp Suite Extension
# This extension processes HTTP traffic from Burp's history for in-scope requests
# and extracts unique HTTP operations with JSON bodies, including GraphQL operations

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JLabel, JProgressBar
from javax.swing import JFileChooser, JOptionPane, SwingConstants, BorderFactory, SwingUtilities
from javax.swing import BoxLayout, JCheckBox, JSeparator, JTabbedPane, JTable
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, Dimension, Font, Color, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import ActionListener
from java.io import File
from java.lang import Thread, Runnable
import json
import re
import base64
from datetime import datetime
from collections import OrderedDict
from urlparse import urlparse
import threading

class BurpExtender(IBurpExtender, ITab, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName("TrafficMiner")
        
        # Initialize UI components
        self._init_ui()
        
        # Add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)
        
        # Storage for processed data
        self.processed_data = []
        self.seen_keys = set()
        self.seen_graphql_bodies = set()
        
        print("TrafficMiner extension loaded successfully!")
    
    def _get_burp_frame(self):
        """Get the main Burp Suite frame for proper dialog parenting in multi-monitor setups"""
        try:
            # First try to get the frame using SwingUtilities from our main panel
            if hasattr(self, '_main_panel') and self._main_panel is not None:
                frame = SwingUtilities.getWindowAncestor(self._main_panel)
                if frame is not None:
                    return frame
            
            # Fallback: try to get any frame that might be the Burp Suite main window
            # This is a backup method in case the main panel isn't properly attached yet
            from java.awt import Frame
            frames = Frame.getFrames()
            for frame in frames:
                if frame.isVisible() and "Burp Suite" in str(frame.getTitle()):
                    return frame
            
            # If we still can't find it, return None (dialogs will center on screen)
            return None
        except Exception as e:
            # In case of any error, return None for safe fallback
            print("TrafficMiner: Could not get Burp frame: %s" % str(e))
            return None
    
    def _init_ui(self):
        """Initialize the user interface with Burp Suite styling"""
        # Main panel with Burp Suite dark theme
        self._main_panel = JPanel(BorderLayout())
        self._main_panel.setBackground(Color(60, 63, 65))  # Burp Suite dark background
        
        # Create header panel
        header_panel = self._create_header_panel()
        self._main_panel.add(header_panel, BorderLayout.NORTH)
        
        # Create main content with tabs
        content_panel = self._create_content_panel()
        self._main_panel.add(content_panel, BorderLayout.CENTER)
        
        # Create status bar
        status_bar = self._create_status_bar()
        self._main_panel.add(status_bar, BorderLayout.SOUTH)
    
    def _create_header_panel(self):
        """Create the header panel with title and controls"""
        header_panel = JPanel(BorderLayout())
        header_panel.setBackground(Color(60, 63, 65))  # Burp Suite header background
        header_panel.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15))
        
        # Title and description
        title_panel = JPanel()
        title_panel.setLayout(BoxLayout(title_panel, BoxLayout.Y_AXIS))
        title_panel.setBackground(Color(60, 63, 65))
        
        title_label = JLabel("TrafficMiner")
        title_label.setFont(Font("Dialog", Font.BOLD, 18))
        title_label.setForeground(Color(187, 187, 187))  # Burp Suite text color
        title_panel.add(title_label)
        
        desc_label = JLabel("Extract unique HTTP operations with JSON bodies from Burp's HTTP history (in-scope only)")
        desc_label.setFont(Font("Dialog", Font.PLAIN, 12))
        desc_label.setForeground(Color(153, 153, 153))  # Burp Suite secondary text
        desc_label.setBorder(BorderFactory.createEmptyBorder(3, 0, 0, 0))
        title_panel.add(desc_label)
        
        header_panel.add(title_panel, BorderLayout.WEST)
        
        # Control buttons panel
        controls_panel = self._create_controls_panel()
        header_panel.add(controls_panel, BorderLayout.EAST)
        
        return header_panel
    
    def _create_controls_panel(self):
        """Create the controls panel with buttons and options"""
        controls_panel = JPanel(GridBagLayout())
        controls_panel.setBackground(Color(60, 63, 65))
        gbc = GridBagConstraints()
        
        # Process button - primary action (Burp Suite orange)
        self._process_button = JButton("Process HTTP History")
        self._process_button.setFont(Font("Dialog", Font.PLAIN, 12))
        self._process_button.setBackground(Color(255, 102, 51))  # Burp Suite orange
        self._process_button.setForeground(Color.WHITE)
        self._process_button.setPreferredSize(Dimension(160, 28))
        self._process_button.addActionListener(ProcessHistoryAction(self))
        self._process_button.setBorderPainted(False)
        self._process_button.setFocusPainted(False)
        
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.insets = Insets(0, 0, 10, 10)
        controls_panel.add(self._process_button, gbc)
        
        # Clear button
        self._clear_button = JButton("Clear")
        self._clear_button.setFont(Font("Dialog", Font.PLAIN, 12))
        self._clear_button.setBackground(Color(69, 73, 74))  # Burp Suite button gray
        self._clear_button.setForeground(Color(187, 187, 187))
        self._clear_button.setPreferredSize(Dimension(70, 28))
        self._clear_button.addActionListener(ClearResultsAction(self))
        self._clear_button.setBorderPainted(False)
        self._clear_button.setFocusPainted(False)
        
        gbc.gridx = 1
        gbc.gridy = 0
        gbc.insets = Insets(0, 0, 10, 10)
        controls_panel.add(self._clear_button, gbc)
        
        # Export button
        self._export_button = JButton("Export JSON")
        self._export_button.setFont(Font("Dialog", Font.PLAIN, 12))
        self._export_button.setBackground(Color(69, 73, 74))  # Burp Suite button gray
        self._export_button.setForeground(Color(187, 187, 187))
        self._export_button.setPreferredSize(Dimension(100, 28))
        self._export_button.addActionListener(ExportAction(self))
        self._export_button.setEnabled(False)
        self._export_button.setBorderPainted(False)
        self._export_button.setFocusPainted(False)
        
        gbc.gridx = 2
        gbc.gridy = 0
        gbc.insets = Insets(0, 0, 10, 0)
        controls_panel.add(self._export_button, gbc)
        
        # Filter options
        filter_panel = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0))
        filter_panel.setBackground(Color(60, 63, 65))
        
        self._include_graphql_checkbox = JCheckBox("GraphQL Operations", True)
        self._include_graphql_checkbox.setFont(Font("Dialog", Font.PLAIN, 11))
        self._include_graphql_checkbox.setForeground(Color(187, 187, 187))
        self._include_graphql_checkbox.setBackground(Color(60, 63, 65))
        filter_panel.add(self._include_graphql_checkbox)
        
        filter_panel.add(JLabel("   "))  # Spacing
        
        self._include_rest_checkbox = JCheckBox("REST APIs", True)
        self._include_rest_checkbox.setFont(Font("Dialog", Font.PLAIN, 11))
        self._include_rest_checkbox.setForeground(Color(187, 187, 187))
        self._include_rest_checkbox.setBackground(Color(60, 63, 65))
        filter_panel.add(self._include_rest_checkbox)
        
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 3
        gbc.insets = Insets(0, 0, 0, 0)
        controls_panel.add(filter_panel, gbc)
        
        return controls_panel
    
    def _create_content_panel(self):
        """Create the main content panel with tabs"""
        # Create tabbed pane for better organization
        self._tabbed_pane = JTabbedPane()
        self._tabbed_pane.setFont(Font("Dialog", Font.PLAIN, 12))
        self._tabbed_pane.setBackground(Color(60, 63, 65))
        self._tabbed_pane.setForeground(Color(187, 187, 187))
        
        # Summary tab with table view
        summary_panel = self._create_summary_tab()
        self._tabbed_pane.addTab("Summary", summary_panel)
        
        # Details tab with text view
        details_panel = self._create_details_tab()
        self._tabbed_pane.addTab("Details", details_panel)
        
        # Progress panel
        progress_panel = self._create_progress_panel()
        
        # Main content container
        content_container = JPanel(BorderLayout())
        content_container.add(progress_panel, BorderLayout.NORTH)
        content_container.add(self._tabbed_pane, BorderLayout.CENTER)
        
        return content_container
    
    def _create_summary_tab(self):
        """Create summary tab with table view"""
        summary_panel = JPanel(BorderLayout())
        summary_panel.setBackground(Color(60, 63, 65))
        summary_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Create table model
        column_names = ["#", "Method", "URL", "Status", "Type", "Operation", "Req Body", "Resp Body"]
        self._table_model = DefaultTableModel(column_names, 0)
        self._summary_table = JTable(self._table_model)
        
        # Style the table to match Burp Suite
        self._summary_table.setFont(Font("Dialog", Font.PLAIN, 11))
        self._summary_table.getTableHeader().setFont(Font("Dialog", Font.BOLD, 11))
        self._summary_table.setRowHeight(20)
        self._summary_table.setBackground(Color(69, 73, 74))  # Burp table background
        self._summary_table.setForeground(Color(187, 187, 187))  # Burp text color
        self._summary_table.setGridColor(Color(43, 43, 43))  # Burp grid color
        self._summary_table.setSelectionBackground(Color(75, 110, 175))  # Burp selection color
        self._summary_table.setSelectionForeground(Color.WHITE)
        self._summary_table.getTableHeader().setBackground(Color(60, 63, 65))
        self._summary_table.getTableHeader().setForeground(Color(187, 187, 187))
        
        # Set column widths
        column_model = self._summary_table.getColumnModel()
        column_widths = [50, 80, 300, 80, 100, 150, 80, 80]
        for i, width in enumerate(column_widths):
            column_model.getColumn(i).setPreferredWidth(width)
        
        table_scroll = JScrollPane(self._summary_table)
        table_scroll.getViewport().setBackground(Color(69, 73, 74))
        table_scroll.setBackground(Color(60, 63, 65))
        
        summary_panel.add(table_scroll, BorderLayout.CENTER)
        
        return summary_panel
    
    def _create_details_tab(self):
        """Create details tab with text view"""
        details_panel = JPanel(BorderLayout())
        details_panel.setBackground(Color(60, 63, 65))
        details_panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        
        # Results text area
        self._results_area = JTextArea()
        self._results_area.setEditable(False)
        self._results_area.setFont(Font("Monospaced", Font.PLAIN, 11))
        self._results_area.setText("No data processed yet. Click 'Process HTTP History' to begin.")
        self._results_area.setBackground(Color(69, 73, 74))  # Burp text area background
        self._results_area.setForeground(Color(187, 187, 187))  # Burp text color
        self._results_area.setCaretColor(Color(187, 187, 187))
        self._results_area.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        results_scroll = JScrollPane(self._results_area)
        results_scroll.getViewport().setBackground(Color(69, 73, 74))
        results_scroll.setBackground(Color(60, 63, 65))
        
        details_panel.add(results_scroll, BorderLayout.CENTER)
        
        return details_panel
    
    def _create_progress_panel(self):
        """Create progress panel"""
        progress_panel = JPanel(BorderLayout())
        progress_panel.setBackground(Color(60, 63, 65))
        progress_panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10))
        progress_panel.setVisible(False)
        
        # Progress bar with Burp Suite styling
        self._progress_bar = JProgressBar()
        self._progress_bar.setStringPainted(True)
        self._progress_bar.setFont(Font("Dialog", Font.PLAIN, 11))
        self._progress_bar.setPreferredSize(Dimension(0, 20))
        self._progress_bar.setBackground(Color(69, 73, 74))
        self._progress_bar.setForeground(Color(255, 102, 51))  # Burp orange
        
        progress_panel.add(self._progress_bar, BorderLayout.CENTER)
        
        self._progress_panel = progress_panel
        return progress_panel
    
    def _create_status_bar(self):
        """Create status bar"""
        status_panel = JPanel(BorderLayout())
        status_panel.setBackground(Color(43, 43, 43))  # Burp status bar color
        status_panel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10))
        
        self._status_label = JLabel("Ready to process HTTP history")
        self._status_label.setFont(Font("Dialog", Font.PLAIN, 11))
        self._status_label.setForeground(Color(187, 187, 187))
        
        self._stats_label = JLabel("")
        self._stats_label.setFont(Font("Dialog", Font.PLAIN, 11))
        self._stats_label.setForeground(Color(153, 153, 153))
        
        status_panel.add(self._status_label, BorderLayout.WEST)
        status_panel.add(self._stats_label, BorderLayout.EAST)
        
        return status_panel
    
    def getTabCaption(self):
        return "TrafficMiner"
    
    def getUiComponent(self):
        return self._main_panel
    
    def parse_headers(self, header_str):
        """Parse HTTP headers string into a dictionary"""
        headers = OrderedDict()
        if not header_str:
            return headers
        lines = header_str.strip().split('\r\n')
        for line in lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    
    def extract_graphql_info(self, request_json_body):
        """Extract GraphQL operation type and name from request body"""
        if not isinstance(request_json_body, dict):
            return None, None
            
        operation_name = request_json_body.get('operationName')
        graphql_query_str = request_json_body.get('query', '')
        
        if graphql_query_str and isinstance(graphql_query_str, str):
            # Find operation type (query/mutation)
            type_match = re.search(r'\s*(query|mutation)\s+', graphql_query_str, re.IGNORECASE)
            graphql_op_type = type_match.group(1).lower() if type_match else "query"
            
            # Find operation name from query if not in operationName
            if not operation_name:
                name_match = re.search(r'\b(query|mutation)\s+([a-zA-Z0-9_]+)', graphql_query_str)
                operation_name = name_match.group(2) if name_match else "Unnamed"
            
            return graphql_op_type, operation_name
        
        return "query", operation_name if operation_name else "UnknownFormat"
    
    def process_http_history(self):
        """Process HTTP history and extract unique operations"""
        try:
            # Get HTTP history from Burp
            http_history = self._callbacks.getProxyHistory()
            total_items = len(http_history)
            
            if total_items == 0:
                self._status_label.setText("No HTTP history found!")
                return
            
            # Show progress bar
            self._progress_panel.setVisible(True)
            self._progress_bar.setMaximum(total_items)
            self._progress_bar.setValue(0)
            
            # Reset storage
            self.processed_data = []
            self.seen_keys = set()
            self.seen_graphql_bodies = set()
            
            processed_count = 0
            
            for i, history_item in enumerate(http_history):
                # Update progress
                self._progress_bar.setValue(i + 1)
                self._progress_bar.setString("Processing item %d of %d" % (i + 1, total_items))
                
                # Only process in-scope requests
                if not self._callbacks.isInScope(history_item.getUrl()):
                    continue
                
                # Get request and response
                request_info = self._helpers.analyzeRequest(history_item)
                response = history_item.getResponse()
                
                if response:
                    response_info = self._helpers.analyzeResponse(response)
                else:
                    response_info = None
                
                # Extract request details
                method = request_info.getMethod()
                url = str(history_item.getUrl())
                
                # Get request body
                request_body_str = ""
                request_json_body = None
                request_bytes = history_item.getRequest()
                
                if request_bytes and request_info.getBodyOffset() < len(request_bytes):
                    request_body_bytes = request_bytes[request_info.getBodyOffset():]
                    if request_body_bytes:
                        try:
                            request_body_str = self._helpers.bytesToString(request_body_bytes)
                            if request_body_str:
                                request_json_body = json.loads(request_body_str)
                        except:
                            request_json_body = None
                
                # Get response details
                status_code = None
                response_json_body = None
                
                if response_info:
                    status_code = response_info.getStatusCode()
                    
                    # Get response body
                    if response and response_info.getBodyOffset() < len(response):
                        response_body_bytes = response[response_info.getBodyOffset():]
                        if response_body_bytes:
                            try:
                                response_body_str = self._helpers.bytesToString(response_body_bytes)
                                # Check if response is JSON
                                response_headers = response_info.getHeaders()
                                content_type = ""
                                for header in response_headers:
                                    if header.lower().startswith("content-type:"):
                                        content_type = header.lower()
                                        break
                                
                                if "application/json" in content_type and response_body_str:
                                    response_json_body = json.loads(response_body_str)
                            except:
                                response_json_body = None
                
                # Check for GraphQL
                graphql_op_type = None
                graphql_op_name = None
                
                if method == "POST" and request_json_body:
                    if 'query' in request_json_body or 'operationName' in request_json_body:
                        graphql_op_type, graphql_op_name = self.extract_graphql_info(request_json_body)
                elif 'graphql' in url.lower():
                    graphql_op_type = "query"
                    graphql_op_name = "UnknownFromURL"
                
                # Create deduplication key
                try:
                    parsed_url = urlparse(url)
                    base_key_part = (method, parsed_url.scheme, parsed_url.netloc, parsed_url.path)
                    
                    if graphql_op_type and graphql_op_name:
                        if graphql_op_type == "query":
                            item_key = base_key_part + (graphql_op_type, graphql_op_name, request_body_str)
                        else:
                            item_key = base_key_part + (graphql_op_type, graphql_op_name)
                    else:
                        item_key = base_key_part
                except:
                    continue
                
                # Deduplication logic
                process_item = False
                if graphql_op_type:
                    if request_body_str not in self.seen_graphql_bodies:
                        self.seen_graphql_bodies.add(request_body_str)
                        process_item = True
                else:
                    if item_key not in self.seen_keys:
                        self.seen_keys.add(item_key)
                        process_item = True
                
                # Apply filters and add to results
                if process_item:
                    include_item = False
                    
                    # Check if should include based on checkboxes
                    if graphql_op_type and self._include_graphql_checkbox.isSelected():
                        include_item = True
                    elif not graphql_op_type and self._include_rest_checkbox.isSelected():
                        # Include if request or response has JSON body
                        if request_json_body is not None or response_json_body is not None:
                            include_item = True
                    
                    if include_item:
                        item_data = {
                            "method": method,
                            "url": url,
                            "status_code": status_code,
                            "request_body": request_json_body,
                            "response_body": response_json_body,
                            "graphql_operation_type": graphql_op_type,
                            "graphql_operation_name": graphql_op_name,
                        }
                        self.processed_data.append(item_data)
                        processed_count += 1
            
            # Hide progress bar
            self._progress_panel.setVisible(False)
            
            # Update UI
            self._update_results_display()
            self._update_summary_table()
            self._export_button.setEnabled(len(self.processed_data) > 0)
            self._status_label.setText("Processing completed successfully")
            self._stats_label.setText("Found %d unique operations from %d total history items" % 
                                     (len(self.processed_data), total_items))
            
        except Exception as e:
            self._progress_panel.setVisible(False)
            self._status_label.setText("Error processing history: %s" % str(e))
            self._stats_label.setText("")
            print("Error processing HTTP history: %s" % str(e))
    
    def _update_results_display(self):
        """Update the results text area"""
        if not self.processed_data:
            self._results_area.setText("No unique operations found matching the selected criteria.")
            return
        
        results_text = "Found %d unique operations:\n\n" % len(self.processed_data)
        
        for i, op in enumerate(self.processed_data):
            results_text += "=== Operation %d ===\n" % (i + 1)
            results_text += "Method: %s\n" % op.get('method', 'N/A')
            results_text += "URL: %s\n" % op.get('url', 'N/A')
            results_text += "Status Code: %s\n" % op.get('status_code', 'N/A')
            
            if op.get('graphql_operation_type'):
                results_text += "GraphQL Operation: %s %s\n" % (
                    op.get('graphql_operation_type', '').upper(),
                    op.get('graphql_operation_name', '')
                )
            
            results_text += "Has Request Body: %s\n" % (op.get('request_body') is not None)
            results_text += "Has Response Body: %s\n" % (op.get('response_body') is not None)
            results_text += "\n"
        
        self._results_area.setText(results_text)
        self._results_area.setCaretPosition(0)  # Scroll to top
    
    def _update_summary_table(self):
        """Update the summary table with processed data"""
        # Clear existing rows
        self._table_model.setRowCount(0)
        
        if not self.processed_data:
            return
        
        # Add data to table
        for i, op in enumerate(self.processed_data):
            method = op.get('method', 'N/A')
            url = op.get('url', 'N/A')
            # Truncate URL if too long
            if len(url) > 60:
                url = url[:57] + "..."
            
            status_code = op.get('status_code', 'N/A')
            
            # Determine operation type
            if op.get('graphql_operation_type'):
                op_type = "GraphQL"
                operation = "%s %s" % (
                    op.get('graphql_operation_type', '').upper(),
                    op.get('graphql_operation_name', '')
                )
            else:
                op_type = "REST API"
                operation = "-"
            
            has_req_body = "Yes" if op.get('request_body') is not None else "No"
            has_resp_body = "Yes" if op.get('response_body') is not None else "No"
            
            row_data = [
                str(i + 1),
                method,
                url,
                str(status_code),
                op_type,
                operation,
                has_req_body,
                has_resp_body
            ]
            
            self._table_model.addRow(row_data)

class ProcessHistoryAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        # Run in separate thread to avoid blocking UI
        thread = Thread(ProcessHistoryRunnable(self.extender))
        thread.start()

class ProcessHistoryRunnable(Runnable):
    def __init__(self, extender):
        self.extender = extender
    
    def run(self):
        self.extender.process_http_history()

class ClearResultsAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        self.extender.processed_data = []
        self.extender.seen_keys = set()
        self.extender.seen_graphql_bodies = set()
        self.extender._results_area.setText("Results cleared. Click 'Process HTTP History' to begin.")
        self.extender._table_model.setRowCount(0)  # Clear table
        self.extender._export_button.setEnabled(False)
        self.extender._status_label.setText("Ready to process HTTP history")
        self.extender._stats_label.setText("")

class ExportAction(ActionListener):
    def __init__(self, extender):
        self.extender = extender
    
    def actionPerformed(self, event):
        if not self.extender.processed_data:
            burp_frame = self.extender._get_burp_frame()
            JOptionPane.showMessageDialog(burp_frame, 
                                        "No data to export. Please process HTTP history first.",
                                        "No Data", JOptionPane.WARNING_MESSAGE)
            return
        
        # Show file chooser
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Save JSON Export")
        
        # Set default filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_filename = "trafficminer_export_%s.json" % timestamp
        file_chooser.setSelectedFile(File(default_filename))
        
        # Show save dialog with Burp frame as parent
        burp_frame = self.extender._get_burp_frame()
        result = file_chooser.showSaveDialog(burp_frame)
        
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            try:
                # Write JSON data to file
                json_data = json.dumps(self.extender.processed_data, indent=2)
                
                with open(str(selected_file.getAbsolutePath()), 'w') as f:
                    f.write(json_data)
                
                burp_frame = self.extender._get_burp_frame()
                JOptionPane.showMessageDialog(burp_frame,
                                            "Data exported successfully to:\n%s" % selected_file.getAbsolutePath(),
                                            "Export Successful", JOptionPane.INFORMATION_MESSAGE)
                
                self.extender._status_label.setText("Export completed successfully")
                self.extender._stats_label.setText("Exported %d operations to %s" % 
                                                   (len(self.extender.processed_data), selected_file.getName()))
                
            except Exception as e:
                burp_frame = self.extender._get_burp_frame()
                JOptionPane.showMessageDialog(burp_frame,
                                            "Error exporting data:\n%s" % str(e),
                                            "Export Error", JOptionPane.ERROR_MESSAGE)
