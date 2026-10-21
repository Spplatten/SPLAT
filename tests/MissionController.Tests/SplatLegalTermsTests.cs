using System.Linq;
using System.Text.RegularExpressions;
using MissionController.Core;
using Xunit;

namespace MissionController.Tests;

public class SplatLegalTermsTests
{
    /// <summary>
    /// The first draft of these documents named a contact address one character away from the
    /// company's, and the AGPL-3.0 that licenses Community was a footnote to a EULA that restricted
    /// it. Both are the kind of defect nobody rereads legal text to find.
    /// </summary>
    [Fact]
    public void EveryDocumentNamesTheCompanysAddress_AndDefersToTheAgpl()
    {
        Assert.Equal("platten.industries@gmail.com", SplatLegalTerms.ContactEmail);
        Assert.Equal(new[] { "eula", "terms", "privacy" }, SplatLegalTerms.AllDocuments.Select(d => d.Key));

        foreach (var doc in SplatLegalTerms.AllDocuments)
        {
            var addresses = Regex.Matches(doc.FullText, @"[\w.+-]+@[\w-]+(?:\.[\w-]+)+").Select(m => m.Value).Distinct();
            Assert.All(addresses, address => Assert.Equal(SplatLegalTerms.ContactEmail, address));
            Assert.Same(doc, SplatLegalTerms.TryGetByKeyOrUri(doc.Uri));
        }

        // The texts wrap at a column, so compare them as prose.
        static string Prose(string text) => Regex.Replace(text, @"\s+", " ");
        Assert.Contains("the AGPL controls", Prose(SplatLegalTerms.EulaText));
        Assert.Contains("the AGPL controls", Prose(SplatLegalTerms.TermsOfUseText));
    }
}
