using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;
using System.Net.Http;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Windows.Threading;

namespace WpfApp1
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
  
    public partial class MainWindow : Window
    {
        string UserIdPath = "./userid.txt";
        string passkey = "";
        Window1 anotherWindow;
        Window2 passkeyWin;
        HttpClient client = new HttpClient();
        string mainurl = "https://chatbackend.stami.tech/";
        string userid;
        DispatcherTimer dispatcherTimer = new DispatcherTimer();
        ListViewItem selectedItem = null;
        
        public MainWindow()
        {
            string userid = "";
            InitializeComponent();
            // Generate new userid if it doesn't exist
            if (File.Exists(this.UserIdPath))
            {
                userid = File.ReadAllText(this.UserIdPath);
            } else
            {
                userid = (new Random()).Next(1000000, 10000000).ToString();
                File.WriteAllText(this.UserIdPath, userid);
            }
            this.mainbutton.Content += " (Id: " + userid + ")";
            this.userid = userid;
            getChats();
            dispatcherTimer.Tick += DispatcherTimer_Tick;
            dispatcherTimer.Interval = new TimeSpan(0, 0, 5);
            dispatcherTimer.Start();


        }

        private void DispatcherTimer_Tick(object sender, EventArgs e)
        {
            this.refresh_messages();
        }

        private void getChats()
        {
            Task<HttpResponseMessage> req = client.GetAsync(this.mainurl + "getchats?" + this.userid);
            req.Wait();
            string result  = req.Result.Content.ReadAsStringAsync().Result;
            string[] chats = result.Split(',');
            this.userlist.Items.Clear();
            for(int i = 0; i < chats.Length; i++)
            {
                ListViewItem itm = new ListViewItem();
                itm.Content = chats[i];
                this.userlist.Items.Add(itm);
            }
       }

        private void mainbutton_Click(object sender, RoutedEventArgs e)
        {
            this.anotherWindow = new Window1();
            this.anotherWindow.Show();
            this.anotherWindow.EnterButton.Click += EnterButton_Click;
        }

        private void EnterButton_Click(object sender, RoutedEventArgs e)
        {
            string filecontents = "";
            if (File.Exists("./mdata.txt"))
            {
                filecontents = File.ReadAllText("./mdata.txt");
            }
            File.WriteAllText("./mdata.txt", filecontents + "\n" + this.anotherWindow.idinput.Text + ";" + this.anotherWindow.passinput.Text);
            this.createChat(this.anotherWindow.idinput.Text);
            this.anotherWindow.Close();
        }
        private void writeMessages(string msgOriginal)
        {
            string[] messages = msgOriginal.Split('`');
            this.messagesSpot.Text = "";
            for(int i = 0; i < messages.Length; i++)
            {
                string[] authorMessage = messages[i].Split('¨');
                string author = authorMessage[0];
                string msg = StringCipher.Decrypt(authorMessage[1], this.passkey);
                if (author == this.userid.ToString())
                {
                    author = "<< ";
                } else author = ">> ";
                this.messagesSpot.Text += author + msg + "\n";
            }
        }

        private void createChat(string id)
        {
            var req = client.GetAsync(this.mainurl + "createchat?" + id + ";" + this.userid);
            req.Wait();
            this.getChats();
        }

        private void userlist_PreviewMouseLeftButtonUp(object sender, MouseButtonEventArgs e)
        {
            this.selectedItem = (ListViewItem)this.userlist.SelectedItem;
            refresh_messages();
        }

        private void refresh_messages()
        {
            
            if (this.selectedItem == null) return;
            string otheruser = this.selectedItem.Content.ToString();
            this.passkey = this.GetPasskey(otheruser);
            if(this.passkey == "")
            {
                this.inputPass();
                return;
            }
            if (otheruser != null)
            {

                Task<HttpResponseMessage> req = client.GetAsync(this.mainurl + "getmessages?" + this.userid + ";" + otheruser);
                req.Wait();
                string result = req.Result.Content.ReadAsStringAsync().Result;
                writeMessages(result);
            }
        }
        private void inputPass()
        {
            if (this.passkeyWin.IsActive) return;
            this.passkeyWin = new Window2();
            this.passkeyWin.Show();
            this.passkeyWin.passkeyButt.Click += PasskeyButt_Click;
        }

        private void PasskeyButt_Click(object sender, RoutedEventArgs e)
        {
            this.passkey = this.passkeyWin.passkeyInput.Text;
            string filecontents = "";
            if (File.Exists("./mdata.txt"))
            {
                filecontents = File.ReadAllText("./mdata.txt");
            }
            File.WriteAllText("./mdata.txt", filecontents + "\n" + this.selectedItem.Content + ";" + this.passkeyWin.passkeyInput.Text);
            this.passkeyWin.Close();
            this.refresh_messages();

        }

        private string GetPasskey(string otheruser)
        {
            if (!File.Exists("./mdata.txt")) return "";
            string[] filecon = File.ReadAllText("./mdata.txt").Split('\n');
            for(int i = 0; i < filecon.Length; i++)
            {
                if(filecon[i].StartsWith(otheruser))
                {
                    return filecon[i].Split(';')[1];
                }
            }
            return "";
        }
        private void SendB_Click(object sender, RoutedEventArgs e)
        {
            if (this.passkey == null) return;
            string encrypted = StringCipher.Encrypt(this.newMsg.Text, this.passkey);
            sendMsg(encrypted);
            this.newMsg.Text = "";
            refresh_messages();
        }


        private void sendMsg(string msg)
        {
            this.selectedItem = (ListViewItem)this.userlist.SelectedItem;
            string otheruser = this.selectedItem.Content.ToString();
            if (otheruser != null)
            {
                Task<HttpResponseMessage> req = client.GetAsync(this.mainurl + "newmessage?" + otheruser + ";" + msg + ";" + this.userid);
                req.Wait();
            }

        }
    }





    public static class StringCipher
    {
        // This constant is used to determine the keysize of the encryption algorithm in bits.
        // We divide this by 8 within the code below to get the equivalent number of bytes.
        private const int Keysize = 256;

        // This constant determines the number of iterations for the password bytes generation function.
        private const int DerivationIterations = 1000;

        public static string Encrypt(string plainText, string passPhrase)
        {
            // Salt and IV is randomly generated each time, but is preprended to encrypted cipher text
            // so that the same Salt and IV values can be used when decrypting.  
            var saltStringBytes = Generate256BitsOfRandomEntropy();
            var ivStringBytes = Generate256BitsOfRandomEntropy();
            var plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var encryptor = symmetricKey.CreateEncryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream())
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                            {
                                cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                                cryptoStream.FlushFinalBlock();
                                // Create the final bytes as a concatenation of the random salt bytes, the random iv bytes and the cipher bytes.
                                var cipherTextBytes = saltStringBytes;
                                cipherTextBytes = cipherTextBytes.Concat(ivStringBytes).ToArray();
                                cipherTextBytes = cipherTextBytes.Concat(memoryStream.ToArray()).ToArray();
                                memoryStream.Close();
                                cryptoStream.Close();
                                return Convert.ToBase64String(cipherTextBytes);
                            }
                        }
                    }
                }
            }
        }

        public static string Decrypt(string cipherText, string passPhrase)
        {
            // Get the complete stream of bytes that represent:
            // [32 bytes of Salt] + [32 bytes of IV] + [n bytes of CipherText]
            byte[] cipherTextBytesWithSaltAndIv;
            try
            {
                cipherTextBytesWithSaltAndIv = Convert.FromBase64String(cipherText);
            } catch
            {
                return "";
            }
            // Get the saltbytes by extracting the first 32 bytes from the supplied cipherText bytes.
            var saltStringBytes = cipherTextBytesWithSaltAndIv.Take(Keysize / 8).ToArray();
            // Get the IV bytes by extracting the next 32 bytes from the supplied cipherText bytes.
            var ivStringBytes = cipherTextBytesWithSaltAndIv.Skip(Keysize / 8).Take(Keysize / 8).ToArray();
            // Get the actual cipher text bytes by removing the first 64 bytes from the cipherText string.
            var cipherTextBytes = cipherTextBytesWithSaltAndIv.Skip((Keysize / 8) * 2).Take(cipherTextBytesWithSaltAndIv.Length - ((Keysize / 8) * 2)).ToArray();

            using (var password = new Rfc2898DeriveBytes(passPhrase, saltStringBytes, DerivationIterations))
            {
                var keyBytes = password.GetBytes(Keysize / 8);
                using (var symmetricKey = new RijndaelManaged())
                {
                    symmetricKey.BlockSize = 256;
                    symmetricKey.Mode = CipherMode.CBC;
                    symmetricKey.Padding = PaddingMode.PKCS7;
                    using (var decryptor = symmetricKey.CreateDecryptor(keyBytes, ivStringBytes))
                    {
                        using (var memoryStream = new MemoryStream(cipherTextBytes))
                        {
                            using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                            using (var streamReader = new StreamReader(cryptoStream, Encoding.UTF8))
                            {
                                return streamReader.ReadToEnd();
                            }
                        }
                    }
                }
            }
        }

        private static byte[] Generate256BitsOfRandomEntropy()
        {
            var randomBytes = new byte[32]; // 32 Bytes will give us 256 bits.
            using (var rngCsp = new RNGCryptoServiceProvider())
            {
                // Fill the array with cryptographically secure random bytes.
                rngCsp.GetBytes(randomBytes);
            }
            return randomBytes;
        }
    }
}



