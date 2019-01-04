namespace AaronLocker
{
    /// <summary>
    /// The kind of rule a rule is
    /// </summary>
    public enum RuleType
    {
        /// <summary>
        /// A rule based on controlling execution of files signed by a specific publisher
        /// </summary>
        Publisher,

        /// <summary>
        /// A rule that controls execution based on a specific file hash
        /// </summary>
        Hash,

        /// <summary>
        /// A rule controlling execution based on path content is executed from
        /// </summary>
        Path,

        /// <summary>
        /// A temporary rule that will be converted into regular rules when realized.
        /// </summary>
        SourcePath
    }
}
