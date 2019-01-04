namespace AaronLocker
{
    /// <summary>
    /// Whether a policy should be enforced
    /// </summary>
    public enum EnforcementMode
    {
        /// <summary>
        /// The policy has yet to be configured
        /// </summary>
        NotConfigured = 1,

        /// <summary>
        /// The policy is designed for audit only
        /// </summary>
        AuditOnly = 2,

        /// <summary>
        /// The policy will be enforced
        /// </summary>
        Enabled = 3
    }
}
