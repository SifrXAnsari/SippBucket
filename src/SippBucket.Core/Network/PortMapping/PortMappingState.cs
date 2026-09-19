namespace SippBucket.Core.Network.PortMapping;

/// <summary>Where a mapping this machine obtained stands.</summary>
public enum PortMappingState
{
    /// <summary>
    /// Obtained and being renewed. Still read <see cref="ActivePortMapping.IsActiveAt"/>, which
    /// also checks the expiry time: a state is only as fresh as the last renewal.
    /// </summary>
    Active = 0,

    /// <summary>
    /// No longer held: a renewal was refused, or no renewal was answered before the mapping
    /// expired. <see cref="ActivePortMapping.LostBecause"/> says which.
    /// </summary>
    Lost = 1,

    /// <summary>Removed on request. Renewal has stopped and the router was asked to delete it.</summary>
    Removed = 2,
}
