using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using VirusTotalNET;
using System.Configuration;
using System.IO;
using VirusTotalNET.Objects;
using RestSharp;
using RestSharp.Serializers;

namespace AVTotalSCTA
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            textBox1.Hide();
            textBox2.Hide();
            textBox3.Hide();
            textBox4.Hide();
            Configuration configManager = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            KeyValueConfigurationCollection confCollection = configManager.AppSettings.Settings;





        }
        private static void PrintScan(ScanResult scanResult)
        {
            
            MessageBox.Show("Scan ID: " + scanResult.ScanId);
            MessageBox.Show("Message: " + scanResult.VerboseMsg);
           // Console.WriteLine();
        }
        public static void splitting(string shavalue)
        {
           
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

        private void button1_Click(object sender, EventArgs e)
        {
            VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;

           
            string chosenfile = "";
            openFileDialog1.InitialDirectory = "C:";
            openFileDialog1.Title = "insert file";
            openFileDialog1.FileName = "";
            openFileDialog1.ShowDialog();
            chosenfile = openFileDialog1.FileName;
            textBox1.Text = chosenfile;


            FileInfo fileInfo = new FileInfo(chosenfile);
           // File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
            string hashreport1 = String.Empty;

            //Check if the file has been scanned before.
            VirusTotalNET.Objects.Report fileReport = virusTotal.GetFileReport(fileInfo);
            bool hasFileBeenScannedBefore = fileReport.ResponseCode == ReportResponseCode.Present;
            DialogResult dialogresult = MessageBox.Show("File has been scan before: " ," hasFileBeenScannedBefore", MessageBoxButtons.YesNo); 
            //If the file has been scanned before, the results are embedded inside the report.
            if (dialogresult == DialogResult.Yes)
            {
          
                PrintScan(fileReport);
              
                string str = Convert.ToString(fileReport.Positives); 
               //string[] splitedStrings = str.Split('-');
               //string requestedValue = splitedStrings[0];
                textBox4.Text = str;
            
                foreach (ScanEngine scan in fileReport.Scans)
               {
   
                   string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                   listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                }
            
            }
            else
            {
                VirusTotalNET.Objects.ScanResult fileResult = virusTotal.ScanFile(fileInfo);
            

                PrintScan(fileResult);
               
                string str = Convert.ToString( fileReport.Positives);
                //string[] splitedStrings = str.Split('-');
               // string requestedValue = splitedStrings[0];
              textBox4.Text = str;
                //textBox4.Text = str;

                foreach (ScanEngine scan in fileReport.Scans)
                {

                    string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                    listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                }
            }

      

        }

        private void button2_Click(object sender, EventArgs e)
        {

            VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);
           string ScanUrl = textBox2.Text; 
            Report urlReport = virusTotal.GetUrlReport(ScanUrl);
            DialogResult dialogresult2 = MessageBox.Show("File has been scan before: ", " hasFileBeenScannedBefore", MessageBoxButtons.YesNo);
            //If the url has been scanned before, the results are embedded inside the report.
            if (dialogresult2 == DialogResult.Yes)
            {
                PrintScan(urlReport);
               string str = urlReport.Resource;


                string[] splitedStrings = str.Split('-');
                string requestedValue = splitedStrings[0];
                textBox4.Text = requestedValue;

                foreach (ScanEngine scan in urlReport.Scans)
                {

                    string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                    listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                }
            }
            else
            {
                ScanResult urlResult = virusTotal.ScanUrl(ScanUrl);
                PrintScan(urlResult);
                string str = urlReport.ScanId;

                string[] splitedStrings = str.Split('-');
                string requestedValue = splitedStrings[0];
                textBox4.Text = requestedValue;

                foreach (ScanEngine scan in urlReport.Scans)
                {

                    string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                    listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                }

            }

         
        }

        private void button3_Click(object sender, EventArgs e)
        {
            VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);
           //create a new array for the hash value//
            List<string> hashes = new List<string>();
            hashes.Add(textBox3.Text);
            //generte the report for the hash value//
            List<Report> reports = virusTotal.GetFileReports(hashes);

             string hashreport = String.Empty;
             hashreport = Convert.ToString(reports[0].Positives) + " out of" + " 52";
             textBox4.Text = hashreport;
             if (hashreport == "positive")
             {

             }

           
             //string hashdetails = String.Empty;
            // hashdetails = Convert.ToString(reports[0].Scans);

             foreach (ScanEngine scan in reports[0].Scans)
             {
                 string[] row1 = { scan.Name, Convert.ToString(scan.Detected) };
                 listView1.Items.Add("Detect:").SubItems.AddRange(row1);
                
             }
            ListViewItem item = new ListViewItem();

            //foreach (ListViewItem item in listView1.Items)
            //{
                 //if (item.SubItems[2].Text == "True")
            if (listView1.Items[0].SubItems[2].Text =="True")


                 {
                     MessageBox.Show(hashreport);
                     listView1.Items[0].SubItems[2].BackColor = Color.Red;


                 }
             //}



        }
         
        
        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            

            if (comboBox1.SelectedItem == "File"){
                textBox2.Hide();
               
                textBox1.Show();
                
                textBox3.Hide();
                
                button1.Show();
                button2.Hide();
                button3.Hide();

            }
            else if (comboBox1.SelectedItem == "Url")
            {
                textBox2.Show();
               
                textBox1.Hide();
                
                textBox3.Hide();
                
                button1.Hide();
                button2.Show();
                button3.Hide();

            }
            else if (comboBox1.SelectedItem == "Hash")
            {
                textBox2.Hide();
               
                textBox1.Hide();
                
                textBox3.Show();
               
                button1.Hide();
                button2.Hide();
                button3.Show();

            } 
        }

    

        private void aPIKeyToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Form3 fm3 = new Form3();

            fm3.ShowDialog();


        }

        private void allProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Form4 fm4 = new Form4();

            fm4.ShowDialog();
        }

        public object _apiKey { get; set; }

        private void saveToolStripMenuItem_Click(object sender, EventArgs e)
        {

        }

        private void asTextToolStripMenuItem_Click(object sender, EventArgs e)
        {
             try
            {    
                string docLoc = "";
                string docSource = "";
                StringBuilder sb;

                SaveFileDialog save = new SaveFileDialog();

                save.Filter = "txt|*.txt";

                save.ShowDialog();
                // Change this to the DataSource FilePath
                StreamWriter sw = new StreamWriter(save.FileName);
                string fileHeaderTxt = "ID>AV_Name>Detection";
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
                            sb.Append(string.Format("{0}>", lvSI.Text));
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

        private void asExcelToolStripMenuItem_Click(object sender, EventArgs e)
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

        private void aboutToolStripMenuItem_Click(object sender, EventArgs e)
        {
            AboutBox1 fm = new AboutBox1();
            fm.ShowDialog();
        }

        private void importToolStripMenuItem_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void newSearchToolStripMenuItem_Click(object sender, EventArgs e)
        {
            
        }
        }


    }

