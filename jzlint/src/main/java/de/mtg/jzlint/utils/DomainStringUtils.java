package de.mtg.jzlint.utils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class DomainStringUtils {

    private DomainStringUtils() {
        // empty
    }

    /**
     * https://github.com/publicsuffix/list/wiki/Format#format
     * <p>
     * A domain is said to match a rule if and only if all of the following conditions are met:
     * When the domain and rule are split into corresponding labels, that the domain contains
     * as many or more labels than the rule.
     * Beginning with the right-most labels of both the domain and the rule, and continuing
     * for all labels in the rule, one finds that for every pair, either they are identical,
     * or that the label from the rule is "*".
     */
    public static boolean domainMatches(String domain, String rule) {

        List<String> domainLabels = DomainStringUtils.getLabels(domain);
        List<String> ruleLabels = DomainStringUtils.getLabels(rule);

        if (ruleLabels.size() > domainLabels.size()) {
            return false;
        }

        for (int i = 0; i < ruleLabels.size(); i++) {
            String ruleLabel = ruleLabels.get(i);
            String domainLabel = domainLabels.get(i);

            if (ruleLabel.equals("*")) {
                return true;
            }

            if (!ruleLabel.equalsIgnoreCase(domainLabel)) {
                return false;
            }
        }

        return true;
    }


    public static List<String> getLabels(String rule) {

        if (rule == null || rule.isEmpty() || rule.trim().isEmpty()) {
            return Collections.emptyList();
        }

        String workingString = rule.trim();

        workingString = StringUtils.removeAllLeadingDots(workingString);
        workingString = StringUtils.removeAllTrailingDots(workingString);

        if (!workingString.contains(".")) {
            return Collections.singletonList(workingString);
        }

        String[] split = workingString.split("\\.");
        ArrayList<String> result = new ArrayList<>(Arrays.asList(split));
        Collections.reverse(result);
        return result;
    }

}
