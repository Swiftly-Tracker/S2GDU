using System.Collections.Concurrent;
using S2GDU.Ida.Index;
using S2GDU.Ida.Model;

namespace S2GDU.Ida.Pathfinder;

public readonly record struct ValidationResult(bool IdentityOk, float Reinforcement, string? FailReason);

internal static class Validator
{
    public static bool IdentityMatches(Identity expected, Identity actual, out string? failReason)
    {
        failReason = null;

        if (expected.ReturnType.Length > 0 && actual.ReturnType.Length > 0 && expected.ReturnType != actual.ReturnType)
        {
            bool expPtr = expected.ReturnType[^1] == '*';
            bool actPtr = actual.ReturnType[^1] == '*';
            if (!(expPtr && actPtr))
            {
                failReason = "return_type";
                return false;
            }
        }

        if (expected.ParamCount > 0 && actual.ParamCount > 0)
        {
            int diff = Math.Abs(expected.ParamCount - actual.ParamCount);
            if (diff > Config.IdentityParamTolerance)
            {
                failReason = "param_count";
                return false;
            }
        }

        return true;
    }

    public static float ReinforcementScore(Reinforcement expected, Reinforcement actual, Identity expectedId, Identity actualId)
    {
        float score = 0f;
        float total = 0f;

        if (expected.Size > 0 && actual.Size > 0)
        {
            uint diff = expected.Size > actual.Size ? expected.Size - actual.Size : actual.Size - expected.Size;
            uint pctTolerance = expected.Size * Config.SizeTolerancePct / 100;
            uint tolerance = Math.Max(pctTolerance, Config.MinSizeToleranceAbs);
            if (diff <= tolerance)
            {
                score += 1f - (float)diff / tolerance;
            }
            else
            {
                float overshoot = (float)(diff - tolerance) / tolerance;
                score -= Math.Min(overshoot, 1f);
            }

            total += 1f;
        }

        if (expected.BbCount > 0 && actual.BbCount > 0)
        {
            int diff = Math.Abs(expected.BbCount - actual.BbCount);
            if (diff <= Config.BbCountTolerance)
            {
                score += 1f - (float)diff / Config.BbCountTolerance;
            }
            else
            {
                float overshoot = (float)(diff - Config.BbCountTolerance) / Config.BbCountTolerance;
                score -= Math.Min(overshoot, 1f);
            }

            total += 1f;
        }

        if (expected.Cyclomatic > 0 && actual.Cyclomatic > 0)
        {
            int diff = Math.Abs(expected.Cyclomatic - actual.Cyclomatic);
            if (diff <= Config.CyclomaticTolerance)
            {
                score += 1f - (float)diff / Config.CyclomaticTolerance;
            }
            else
            {
                float overshoot = (float)(diff - Config.CyclomaticTolerance) / Config.CyclomaticTolerance;
                score -= Math.Min(overshoot, 1f);
            }

            total += 1f;
        }

        if (expected.CallerCount > 0 && actual.CallerCount > 0)
        {
            uint diff = expected.CallerCount > actual.CallerCount ? expected.CallerCount - actual.CallerCount : actual.CallerCount - expected.CallerCount;
            uint tolerance = expected.CallerCount * Config.CallerTolerancePct / 100;
            if (tolerance > 0 && diff <= tolerance)
            {
                score += 1f - (float)diff / tolerance;
            }

            total += 1f;
        }

        if (expected.CalleeCount > 0 && actual.CalleeCount > 0)
        {
            uint diff = expected.CalleeCount > actual.CalleeCount ? expected.CalleeCount - actual.CalleeCount : actual.CalleeCount - expected.CalleeCount;
            uint tolerance = expected.CalleeCount * Config.CalleeTolerancePct / 100;
            if (tolerance > 0 && diff <= tolerance)
            {
                score += 1f - (float)diff / tolerance;
            }

            total += 1f;
        }

        {
            uint expF = expectedId.StructFlags;
            uint actF = actualId.StructFlags;
            uint allF = expF | actF;
            if (allF != 0)
            {
                uint commonF = expF & actF;
                int commonN = 0;
                int allN = 0;
                for (uint bit = 1; bit <= allF; bit <<= 1)
                {
                    if ((allF & bit) != 0)
                    {
                        allN++;
                    }

                    if ((commonF & bit) != 0)
                    {
                        commonN++;
                    }
                }

                if (allN > 0)
                {
                    score += (float)commonN / allN;
                }

                total += 1f;
            }
        }

        if (expected.Constants.Count > 0 && actual.Constants.Count > 0)
        {
            int i = 0, j = 0, common = 0;
            while (i < expected.Constants.Count && j < actual.Constants.Count)
            {
                if (expected.Constants[i] == actual.Constants[j])
                {
                    common++;
                    i++;
                    j++;
                }
                else if (expected.Constants[i] < actual.Constants[j])
                {
                    i++;
                }
                else
                {
                    j++;
                }
            }

            int totalUnique = expected.Constants.Count + actual.Constants.Count - common;
            if (totalUnique > 0)
            {
                score += (float)common / totalUnique;
            }

            total += 1f;
        }

        {
            if (expectedId.HasSwitch == actualId.HasSwitch)
            {
                score += 1f;
            }

            total += 1f;
        }

        return total > 0f ? score / total : 0f;
    }

    public static ValidationResult ValidateCandidate(
        GlobalIndex index,
        ConcurrentDictionary<ulong, ValidationResult> cache,
        ulong candidateEa,
        Identity expectedId,
        Reinforcement expectedRf)
    {
        if (cache.TryGetValue(candidateEa, out var cached))
        {
            return cached;
        }

        var f = index.FuncByStart(candidateEa);
        var actualId = f?.Identity ?? new Identity();
        var actualRf = f?.Reinforcement ?? new Reinforcement();

        bool identityOk = IdentityMatches(expectedId, actualId, out string? failReason);

        if (identityOk && expectedRf.Size > 0 && actualRf.Size > 0)
        {
            bool expTiny = expectedRf.Size <= 16;
            bool actTiny = actualRf.Size <= 16;
            if (expTiny != actTiny)
            {
                identityOk = false;
                failReason = "tiny_size_mismatch";
            }
            else if (expTiny && actTiny)
            {
                uint larger = Math.Max(expectedRf.Size, actualRf.Size);
                uint smaller = Math.Min(expectedRf.Size, actualRf.Size);
                if (smaller > 0 && larger > smaller * 2)
                {
                    identityOk = false;
                    failReason = "tiny_size_mismatch";
                }
            }
        }

        float reinforcement = ReinforcementScore(expectedRf, actualRf, expectedId, actualId);

        var result = new ValidationResult(identityOk, reinforcement, failReason);
        cache[candidateEa] = result;
        return result;
    }
}
