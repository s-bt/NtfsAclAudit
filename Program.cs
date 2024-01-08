using CommandLine;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using CommandLine;
using CommandLine.Text;
using System.Threading;
using static NtfsAuditV2.Program;
using System.Data;
using System.Security.Cryptography;
using System.Diagnostics;

namespace NtfsAuditV2
{
    internal class Program
    {
        public static async Task FileWriteAsync(string filePath, string message, bool append = true)
        {
            using (FileStream stream = new FileStream(filePath, append ? FileMode.Append : FileMode.Create, FileAccess.Write, FileShare.None, 4096, true))
            using (StreamWriter sw = new StreamWriter(stream))
            {
                await sw.WriteLineAsync(message);
            }
        }

        private static AuthorizationRuleCollection GetFileAccessRule(string path, string outputFile)
        {
            AuthorizationRuleCollection retVal = new AuthorizationRuleCollection();
            try
            {
                FileInfo fileInfo = new FileInfo(path);
                FileSecurity acl = fileInfo.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                retVal = acl.GetAccessRules(true, true, typeof(NTAccount));
            } catch
            {
                FileWriteAsync(outputFile, $"Error;;;{path.ToString()};;");
            }
            return retVal;
        }

        private static AuthorizationRuleCollection GetDirectoryAccessRule(string path, string outputFile)
        {
            AuthorizationRuleCollection retVal = new AuthorizationRuleCollection();
            try
            {
                DirectoryInfo dirInfo = new DirectoryInfo(path);
                DirectorySecurity acl = dirInfo.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                retVal = acl.GetAccessRules(true, true, typeof(NTAccount));
            }
            catch
            {
                FileWriteAsync(outputFile, $"Error;;;{path.ToString()};;");
            }
            return retVal;
        }

        private static async Task ProcessAccessRules(string path, AuthorizationRuleCollection rules, string outputFile, string type, bool excludeInherited=true)
        {
            foreach (FileSystemAccessRule rule in rules)
            {
                if (rule.IsInherited == true && excludeInherited == true)
                {
                    continue;
                }

                string[] DefaultHighValue = { "S-1-5-18", "S-1-5-32-544", "S-1-5-21-1020856154-1723102393-631647523-512", "S-1-5-21-1020856154-1723102393-631647523-500" };

                SecurityIdentifier sid;

                try
                {
                    NTAccount account = new NTAccount(rule.IdentityReference.Value);
                    sid = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));
                }
                catch (Exception e)
                {
                    //Console.WriteLine( $"[-] Error getting sid:{e.Message}" );
                    continue;
                }

                if (DefaultHighValue.Contains(sid.Value))
                {
                    continue;
                }

                try
                {
                    if (rule.FileSystemRights.HasFlag(FileSystemRights.ChangePermissions) || rule.FileSystemRights.HasFlag(FileSystemRights.FullControl) || rule.FileSystemRights.HasFlag(FileSystemRights.Modify) || rule.FileSystemRights.HasFlag(FileSystemRights.TakeOwnership) || rule.FileSystemRights.HasFlag(FileSystemRights.FullControl) || rule.FileSystemRights.HasFlag(FileSystemRights.Write) || rule.FileSystemRights.HasFlag(FileSystemRights.WriteData) || rule.FileSystemRights.HasFlag(FileSystemRights.AppendData) || rule.FileSystemRights.HasFlag(FileSystemRights.CreateDirectories) || rule.FileSystemRights.HasFlag(FileSystemRights.CreateFiles))
                    {
                        await FileWriteAsync(outputFile, $"Write;{type};{sid};{path.ToString()};{rule.IdentityReference.ToString()};{rule.FileSystemRights.ToString()}");
                        //Console.WriteLine($"Write;{type};{sid};{path.ToString()};{rule.IdentityReference.ToString()};{rule.FileSystemRights.ToString()}");
                    }
                    else if (rule.FileSystemRights.HasFlag(FileSystemRights.Read) || rule.FileSystemRights.HasFlag(FileSystemRights.ReadData))
                    {
                        await FileWriteAsync(outputFile, $"Read;{type};{sid};{path.ToString()};{rule.IdentityReference.ToString()};{rule.FileSystemRights.ToString()}");
                        //Console.WriteLine($"Read;{type};{sid};{path.ToString()};{rule.IdentityReference.ToString()};{rule.FileSystemRights.ToString()}");
                    }
                }
                catch (Exception e)
                {
                    await FileWriteAsync(outputFile, $"Error;;;{path.ToString()};;");
                    Console.WriteLine($"[-] Error testing permissions:{e.Message}");
                    continue;
                }
            }
        }

        private static async Task GetAcls(string path, string outputFile, bool isFile = false, bool excludeInherited = true)
        {
            AuthorizationRuleCollection rules;
            var type = (isFile == true) ? "file" : "directory";

            try
            {
                if (isFile)
                {
                    rules = GetFileAccessRule(path, outputFile);
                }
                else
                {
                    rules = GetDirectoryAccessRule(path, outputFile);
                }
            }
            catch (Exception e)
            {
                await FileWriteAsync(outputFile, $"Error;;;{path.ToString()};;");
                Console.WriteLine($"[-] Error getting acl : {e.Message}");
                return;
            }

            ProcessAccessRules(path, rules, outputFile, type, excludeInherited);
        }

        public static void GetFileAndDirectories(string rootDirectory, string outputFile)
        {
            var fileOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
            };

            var directoryOptions = new EnumerationOptions
            {
                IgnoreInaccessible = true,
                RecurseSubdirectories = true,
            };


            try
            {
                foreach (string directory in Directory.EnumerateDirectories(rootDirectory, "*", directoryOptions))
                {
                    string path = directory;
                    try
                    {
                        GetAcls(path, outputFile);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error doing directory stuff:{e.Message}");
                        continue;
                    }
                    try
                    {
                        foreach (string file in Directory.EnumerateFiles(directory, "*", fileOptions))
                        {
                            string p = file;
                            try
                            {
                                GetAcls(p, outputFile, true);
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine($"[-] Error doing file stuff:{e.Message}");
                                continue;
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine($"[-] Error finding files:{e.Message}");
                        continue;
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine($"[-] Error finding directories:{e.Message}");
            }
        }

        public class Options
        {
            [Option('p', "path", Required = true, HelpText = "Path to scan.")]
            public string Path { get; set; }

            [Option('o', "output-file", Required = false, HelpText = "Output file path.")]
            public string OutputFile { get; set; }
        }

        private static int Main(string[] args)
        {
            string path = "";
            string outputFile = Environment.GetEnvironmentVariable("temp") + "\\ntfsaudit.txt";
            Parser.Default.ParseArguments<Options>(args)
            .WithParsed(options =>
            {

                if (string.IsNullOrEmpty(options.Path))
                {
                    Console.WriteLine("[-] You need to specify a target directory to scan");
                    return;
                }
                else
                {
                    path = options.Path;
                }

                // If the OutputFile parameter has been set, we use it, otherwise we write the file to temp
                if (!string.IsNullOrWhiteSpace(options.OutputFile))
                {
                    outputFile = options.OutputFile;
                }
            });


            if (File.Exists(outputFile))
            {
                try
                {
                    File.Delete(outputFile);
                }
                catch
                {
                    Console.WriteLine($"[-] Unable to delete old output file '{outputFile}'. Exiting.");
                    return -1;
                }
            }

            var outputDirectory = Path.GetDirectoryName(outputFile);
            if (!Directory.Exists(outputDirectory))
            {
                try
                {
                    Directory.CreateDirectory(outputDirectory);
                }
                catch (Exception e)
                {
                    Console.WriteLine($"[-] Could not create output directory '{outputDirectory}':\t{e.Message}");
                    return -1;
                }
            }
            else
            {
                Console.WriteLine($"[*] Scanning '{path.ToString()}' and writing output to '{outputFile}'");
            }

            if (Directory.Exists(path) == false)
            {
                Console.WriteLine($"[-] Directory '{path}' does not exist");
                return -1;
            }

            FileWriteAsync(outputFile, "Result;objectType;SID;Path;Account;FilesystemRights", false);
            
            // Get the acl for the root directory, before continuing
            GetAcls(path, outputFile,false,false);
            
            // Get the acls for all subdirectories and files
            GetFileAndDirectories(path, outputFile);
            return 0;
        }

    }
}