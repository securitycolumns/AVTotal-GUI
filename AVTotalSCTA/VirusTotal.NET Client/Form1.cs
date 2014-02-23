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

namespace VirusTotalNETClient
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();

        }
        private const string ScanUrl = "http://www.google.com/";
        private void button1_Click(object sender, EventArgs e)
        {
            VirusTotal virusTotal = new VirusTotal(System.Configuration.ConfigurationManager.AppSettings["ApiKey"]);

            //Use HTTPS instead of HTTP
            virusTotal.UseTLS = true;

            //Create the EICAR test virus. See http://www.eicar.org/86-0-Intended-use.html
            string chosenfile = "";
            openFileDialog1.InitialDirectory = "C:";
            openFileDialog1.Title = "insert file";
            openFileDialog1.FileName = "";
            openFileDialog1.ShowDialog();
            chosenfile = openFileDialog1.FileName;
            textBox1.Text = chosenfile;

            
            FileInfo fileInfo = new FileInfo(textBox1.Text);
             File.WriteAllText(fileInfo.FullName, @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

            //Check if the file has been scanned before.
            VirusTotalNET.Objects.Report fileReport = virusTotal.GetFileReport(fileInfo);

            bool hasFileBeenScannedBefore = fileReport.ResponseCode == ReportResponseCode.Present;

            Console.WriteLine("File has been scanned before: " + (hasFileBeenScannedBefore ? "Yes" : "No"));

            //If the file has been scanned before, the results are embedded inside the report.
            if (hasFileBeenScannedBefore)
            {
                PrintScan(fileReport);
            }
            else
            {
                VirusTotalNET.Objects.ScanResult fileResult = virusTotal.ScanFile(fileInfo);
                PrintScan(fileResult);
            }

            Console.WriteLine();

            Report urlReport = virusTotal.GetUrlReport(ScanUrl);

            bool hasUrlBeenScannedBefore = urlReport.ResponseCode == ReportResponseCode.Present;
            Console.WriteLine("URL has been scanned before: " + (hasUrlBeenScannedBefore ? "Yes" : "No"));

            //If the url has been scanned before, the results are embedded inside the report.
            if (hasUrlBeenScannedBefore)
            {
                PrintScan(urlReport);
            }
            else
            {
                ScanResult urlResult = virusTotal.ScanUrl(ScanUrl);
                PrintScan(urlResult);
            }

           Console.WriteLine("Press a key to continue");
           Console.ReadLine();
        }

        private static void PrintScan(ScanResult scanResult)
        {
            Console.WriteLine("Scan ID: " + scanResult.ScanId);
            Console.WriteLine("Message: " + scanResult.VerboseMsg);
            Console.WriteLine();
        }

        private static void PrintScan(Report report)
        {
            Console.WriteLine("Scan ID: " + report.ScanId);
            Console.WriteLine("Message: " + report.VerboseMsg);

            if (report.ResponseCode == ReportResponseCode.Present)
            {
                foreach (ScanEngine scan in report.Scans)
                {
                    Console.WriteLine("{0,-25} Detected: {1}", scan.Name, scan.Detected);
                }
            }

            Console.WriteLine();
        }
    }
}
