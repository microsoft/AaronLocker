using System;

namespace AaronLocker
{
    /// <summary>
    /// The various rule scope types available in an AaronLocker based Applocker Rule
    /// </summary>
    [Flags]
    public enum Scope
    {
        /// <summary>
        /// The rule applies to executables
        /// </summary>
        Exe = 1,

        /// <summary>
        /// The rule applies to Dynamic Link Libraries
        /// </summary>
        Dll = 2,

        /// <summary>
        /// The rule applies to script files
        /// </summary>
        Script = 4,

        /// <summary>
        /// The default package applies to executables, dlls and script files
        /// </summary>
        Default = 7,

        /// <summary>
        /// The rule applies to installer files
        /// </summary>
        Msi = 8,

        /// <summary>
        /// The rule applies to AppX UWP Apps
        /// </summary>
        AppX = 16,

        /// <summary>
        /// The rule applies to all types of files
        /// </summary>
        All = 31
    }
}
