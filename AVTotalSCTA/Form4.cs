using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Management;
using System.Security.Cryptography;
using System.IO;
using VirusTotalNET;
using Microsoft.Office.Interop.Excel;
using System.Reflection;
using VirusTotalNET.Objects;

namespace AVTotalSCTA
{
    public partial class Form4 : Form
    {
        public Form4()
        {
            InitializeComponent();
        }

      

        private void button1_Click(object sender, EventArgs e)
        {
            string strProcessDetails = String.Empty;

            Process[] procs = Process.GetProcesses();
            foreach (Process proc in procs)
            {

                try
                {
                    string strprocesshash = String.Empty;
                    string detectionhash = String.Empty;
                    int processId = proc.Id;
                    Process procID = Process.GetProcessById(processId);
                    strProcesspath = (ProcessExecutablePath(procID));
                    strprocesshash = (Processhash(strProcesspath));
                    //Stopwatch sw = new Stopwatch();
                    //sw.Start();
                    //while (sw.Elapsed < TimeSpan.FromMinutes(1))
                    //{
                       // detectionhash = (hashdetection(strprocesshash));
                    //}
                    string[] row1 = { proc.ProcessName, strProcesspath, strprocesshash, detectionhash };
                    listView1.Items.Add(Convert.ToString(proc.Id)).SubItems.AddRange(row1);
                    listView1.BackColor = Color.Snow;
                    listView1.ForeColor = Color.MediumBlue;
                }
                catch (Win32Exception)
                {

                }

            }
  
    }
        private void contextMenuStrip1_ItemClicked(object sender, ToolStripItemClickedEventArgs e)
        {
            if (e.ClickedItem.Text == "Copy")
            {
                //MessageBox.Show(e.ClickedItem.Text);//Write your copy code here  

                for (int i = 0; i < listView1.Items.Count; i++)
                {
                    if (listView1.Items[i].Selected)
                        continue;
                    else
                        listView1.Items[i].Remove();
                }
            }
        } 

        private void Form4_Load(object sender, EventArgs e)
        {
    
            
            listView1.View = View.Details;
            // Allow the user to edit item text.
            listView1.LabelEdit = true;
            // Allow the user to rearrange columns.
            listView1.AllowColumnReorder = true;
            // Display check boxes.
            listView1.CheckBoxes = true;
            // Select the item and subitems when selection is made.
            listView1.FullRowSelect = true;
            // Display grid lines.
            listView1.GridLines = true;
            // Sort the items in the list in ascending order.
            listView1.Sorting = SortOrder.Ascending;
           
         
        }

        static private string hashdetection(string hashID)
        {
            string detevalue = String.Empty;

            try
            {

                        VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);
                        //create a new array for the hash value//
                        List<string> hashes = new List<string>();
                        hashes.Add(hashID);
                        //generte the report for the hash value//
                        List<VirusTotalNET.Objects.Report> reports = virusTotal.GetFileReports(hashes);
                        detevalue = Convert.ToString(reports[0].Positives) + " out of " + " 52";
                        return detevalue;
                  
            }
         
            
            catch { 
            
            }
           
            return "not detected";
      
        }
           

        private string ProcessExecutablePath(Process[] procs)
        {
            throw new NotImplementedException();
        }
        static private string ProcessExecutablePath(Process process)
        {
            try
            {
                return process.MainModule.FileName;
            }
            catch
            {
                string query = "SELECT ExecutablePath, ProcessID FROM Win32_Process";
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(query);

                foreach (ManagementObject item in searcher.Get())
                {
                    object id = item["ProcessID"];
                    object path = item["ExecutablePath"];

                    if (path != null && id.ToString() == process.Id.ToString())
                    {
                        return path.ToString();
                    }
                }
            }

            return "restricted";
        }

        static private string Processhash(string strProcesspath)
        {
            try
            {
                using (var md5 = new MD5CryptoServiceProvider())
                {
                    var buffer = md5.ComputeHash(File.ReadAllBytes(strProcesspath));
                    var sb = new StringBuilder();
                    for (int i = 0; i < buffer.Length; i++)
                    {
                        sb.Append(buffer[i].ToString("x2"));
                    }
                    return sb.ToString();
                }
              
             }
            catch
            {
 
            }

            return "000000000000000000000000000000000000000000";
        }


        public string strProcesspath { get; set; }

        private void listView1_SelectedIndexChanged(object sender, EventArgs e)
        {
            //Point mousePos = listView1.PointToClient(Control.MousePosition);
            //ListViewHitTestInfo hitTest = listView1.HitTest(mousePos);
            //int columnIndex = hitTest.Item.SubItems.IndexOf(hitTest.SubItem);
            ////Clipboard.SetText(this.listView1.SelectedItems.ToString());
        }
        
        private void listView1_MouseClick(object sender, MouseEventArgs e)
        {
            if (e.Button == MouseButtons.Right)
            {
                //contextMenuStrip1_ItemClicked.
                contextMenuStrip1.Show();
            }
        }

        private void contextMenuStrip1_Opening(object sender, CancelEventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (listView1.SelectedItems.Count != 0)
            {
                Clipboard.SetText(listView1.SelectedItems[0].Text);
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
              try
            {    
                string docLoc = "";
                string docSource = "";
                StringBuilder sb;
                // Change this to the DataSource FilePath
                StreamWriter sw = new StreamWriter("Test2.txt");
                string fileHeaderTxt = "ID!name!address1!Path!Hash!Detection";
                sb = new StringBuilder();
                sb.Append(fileHeaderTxt);
                sw.WriteLine(sb.ToString());
                sb.Clear();

                if (listView1.Items.Count > 0)
                {
                    foreach (ListViewItem lvI in listView1.Items)
                    {
                        sb = new StringBuilder();
                        foreach (ListViewItem.ListViewSubItem lvSI in lvI.SubItems)
                        {
                            sb.Append(string.Format("{0}!", lvSI.Text));
                        }
                        sw.WriteLine(sb.ToString());
                    }
                    sw.WriteLine();
                }
                //sb.Clear();
                sw.Close();
                MessageBox.Show("Complete");

          
            }
            catch (Exception ex)
            {
                MessageBox.Show("Source:\t" + ex.Source + "\nMessage: \t" + ex.Message + "\nData:\t" + ex.Data);
            }
            finally
            {
                //
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {

            Microsoft.Office.Interop.Excel.Application app = new Microsoft.Office.Interop.Excel.Application();
            app.Visible = true;
            Microsoft.Office.Interop.Excel.Workbook wb = app.Workbooks.Add(1);
            Microsoft.Office.Interop.Excel.Worksheet ws = (Microsoft.Office.Interop.Excel.Worksheet)wb.Worksheets[1];
            int i = 1;
            int i2 = 1;
            foreach (ListViewItem lvi in listView1.Items)
            {
                i = 1;
                foreach (ListViewItem.ListViewSubItem lvs in lvi.SubItems)
                {
                    ws.Cells[i2, i] = lvs.Text;
                    i++;
                }
                i2++;
            }
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
           

            }

        private void button5_Click(object sender, EventArgs e)
        {
            string detectionhash = String.Empty;


                try
                {
                   // MessageBox.Show(listView1.FocusedItem.);

                    string id = listView1.FocusedItem.SubItems[3].Text;

                        detectionhash = (hashdetection(id));
                        MessageBox.Show(detectionhash);
                    
                    
                  
                    //string id = 
                    
                    

                    
                }
                catch (Win32Exception)
                {

                }

            
  
        }

        private void button2_Click_1(object sender, EventArgs e)
        {
            VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;


            string chosenfile = listView1.FocusedItem.SubItems[2].Text; ;
          


            FileInfo fileInfo = new FileInfo(chosenfile);
            // File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            string hashreport1 = String.Empty;

            //Check if the file has been scanned before.
            VirusTotalNET.Objects.Report fileReport = virusTotal.GetFileReport(fileInfo);
            bool hasFileBeenScannedBefore = fileReport.ResponseCode == ReportResponseCode.Present;
            DialogResult dialogresult = MessageBox.Show("File has been scan before: ", " hasFileBeenScannedBefore", MessageBoxButtons.YesNo);
            //If the file has been scanned before, the results are embedded inside the report.
            if (dialogresult == DialogResult.Yes)
            {

                PrintScan(fileReport);

                string str = Convert.ToString(fileReport.Positives);
                //string[] splitedStrings = str.Split('-');
                //string requestedValue = splitedStrings[0];
                //textBox4.Text = str;

                foreach (ScanEngine scan in fileReport.Scans)
                {

                    //string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                    //listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                    MessageBox.Show(scan.Result);
                }

            }
            else
            {
                VirusTotalNET.Objects.ScanResult fileResult = virusTotal.ScanFile(fileInfo);


                PrintScan(fileResult);

                string str = Convert.ToString(fileReport.Positives);
                //string[] splitedStrings = str.Split('-');
                // string requestedValue = splitedStrings[0];
                //textBox4.Text = str;
                //textBox4.Text = str;

                foreach (ScanEngine scan in fileReport.Scans)
                {

                    //string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                    //listView1.Items.Add("Detect:").SubItems.AddRange(row1);

                    MessageBox.Show(scan.Result);

                }
            }
        }
            private static void PrintScan(ScanResult scanResult)
        {
            
            MessageBox.Show("Scan ID: " + scanResult.ScanId);
            MessageBox.Show("Message: " + scanResult.VerboseMsg);
           // Console.WriteLine();
        }
            private static void PrintScan(Report report)
            {
                MessageBox.Show("Scan ID: " + report.ScanId);
                MessageBox.Show("Message: " + report.VerboseMsg);

                //if (report.ResponseCode == ReportResponseCode.Present)
                // {
                //    foreach (ScanEngine scan in report.Scans)
                //   {

                //        Console.WriteLine("{0,-25} Detected: {1}", scan.Name, scan.Detected);
                //   }
                // }

                //  Console.WriteLine();
            }

        }
        } 
    
       


    