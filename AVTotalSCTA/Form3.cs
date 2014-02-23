using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Configuration;

namespace AVTotalSCTA
{
    public partial class Form3 : Form
    {
        public Form3()
        {
            InitializeComponent();
        }

     

        private void button1_Click(object sender, EventArgs e)
        {
           
            Configuration configManager = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);
            KeyValueConfigurationCollection confCollection = configManager.AppSettings.Settings;
            string apikey = textBox1.Text;
            string newapi = textBox2.Text;
            string confirmapi = textBox3.Text;
            
            if( newapi == confirmapi) {

            confCollection["ApiKey"].Value = newapi;
            configManager.Save(ConfigurationSaveMode.Modified, true);
            configManager.AppSettings.SectionInformation.ForceSave = true;


            ConfigurationManager.RefreshSection("appSettings");
           
            MessageBox.Show("Changing is done");
            }
                else
                {
                
                MessageBox.Show("The API key are not matched");
                }
            
            }

        private void Form3_Load(object sender, EventArgs e)
        {
            string apivalue= "";
            apivalue = ConfigurationManager.AppSettings["ApiKey"];
            textBox1.Text = apivalue;
            
        }
    }
}
