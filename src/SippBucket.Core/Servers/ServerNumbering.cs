namespace SippBucket.Core.Servers;

/// <summary>One install's claim to a number for its server.</summary>
/// <param name="Device">The install that made the claim.</param>
/// <param name="Number">The number, 1 or more.</param>
/// <param name="Numbered">When the install took it.</param>
public sealed record NumberClaim(string Device, int Number, DateTimeOffset Numbered);

/// <summary>
/// "Server 1", "Server 2": the rule that gives each of the person's servers a number, the same
/// on every machine, without anyone assigning or approving anything (docs/SERVER-ID.md).
/// </summary>
/// <remarks>
/// <para>
/// <b>Claims.</b> Each install claims a number for its server and says when it took it. A new
/// install claims 1 at its first start: alone, it is the first. Its claim travels in its
/// <c>sippbucket.server/1</c> record, and each server passes on the claims it has heard to the
/// person's other machines, so a clash is seen even between two machines that are not paired
/// with each other directly.
/// </para>
/// <para>
/// <b>The fixed rule, decided while building Server.ID.</b>
/// </para>
/// <list type="number">
/// <item><description>A server's claim is the earliest of its installs' claims, so a reinstalled
/// machine, or the other Windows on a dual-boot board, carries the board's number
/// forward.</description></item>
/// <item><description>Claims are taken earliest first; two taken in the same instant, the lower
/// permanent ID first, compared as text. The first claim to a number keeps it. Machines that
/// were installed first keep their numbers, which is "the first is Server 1, the next Server
/// 2".</description></item>
/// <item><description>A server whose claim lost, or that has made none, takes the lowest number
/// that no claim holds, losers before servers with no claim, each in the order of step 2. So
/// only the machine that clashed moves; nothing else is renumbered.</description></item>
/// </list>
/// <para>
/// Every server that knows the same claims reaches the same numbers. Clocks decide who was
/// first, and a wrong clock can only change who keeps a contested number: it is a display
/// question, never a sync failure, and a number never wins a conflict or grants trust.
/// </para>
/// </remarks>
public static class ServerNumbering
{
    /// <summary>Resolves every server's number from the claims known.</summary>
    /// <param name="servers">Every server known, by permanent ID, each with its installs' claims.</param>
    /// <returns>Each server's number, by permanent ID.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="servers"/> was null.</exception>
    public static IReadOnlyDictionary<string, int> Resolve(IReadOnlyDictionary<string, IReadOnlyList<NumberClaim>> servers)
    {
        ArgumentNullException.ThrowIfNull(servers);

        var claims = new List<(string Permanent, NumberClaim Claim)>();
        var unclaimed = new List<string>();

        foreach (var (permanent, installs) in servers)
        {
            var earliest = Earliest(installs);
            if (earliest is null)
            {
                unclaimed.Add(permanent);
            }
            else
            {
                claims.Add((permanent, earliest));
            }
        }

        claims.Sort(static (a, b) => Order(a.Permanent, a.Claim, b.Permanent, b.Claim));
        unclaimed.Sort(StringComparer.Ordinal);

        var held = claims.Select(c => c.Claim.Number).ToHashSet();
        var used = new HashSet<int>();
        var numbers = new Dictionary<string, int>(StringComparer.Ordinal);
        var losers = new List<string>();

        foreach (var (permanent, claim) in claims)
        {
            if (used.Add(claim.Number))
            {
                numbers[permanent] = claim.Number;
            }
            else
            {
                losers.Add(permanent);
            }
        }

        foreach (var permanent in losers.Concat(unclaimed))
        {
            var number = 1;
            while (used.Contains(number) || held.Contains(number))
            {
                number++;
            }

            used.Add(number);
            numbers[permanent] = number;
        }

        return numbers;
    }

    /// <summary>A server's claim: the earliest of its installs' claims, or null when none has claimed.</summary>
    /// <param name="installs">Its installs' claims.</param>
    /// <returns>The claim that stands for the server.</returns>
    public static NumberClaim? Earliest(IEnumerable<NumberClaim> installs)
    {
        ArgumentNullException.ThrowIfNull(installs);

        NumberClaim? earliest = null;
        foreach (var claim in installs)
        {
            if (claim.Number < 1)
            {
                continue;
            }

            if (earliest is null ||
                claim.Numbered < earliest.Numbered ||
                (claim.Numbered == earliest.Numbered && claim.Number < earliest.Number) ||
                (claim.Numbered == earliest.Numbered && claim.Number == earliest.Number &&
                 string.CompareOrdinal(claim.Device, earliest.Device) < 0))
            {
                earliest = claim;
            }
        }

        return earliest;
    }

    private static int Order(string leftPermanent, NumberClaim left, string rightPermanent, NumberClaim right)
    {
        var byTime = left.Numbered.CompareTo(right.Numbered);
        return byTime != 0 ? byTime : string.CompareOrdinal(leftPermanent, rightPermanent);
    }
}
