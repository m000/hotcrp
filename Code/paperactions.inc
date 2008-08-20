<?php

class PaperActions {

    function setDecision($prow) {
	global $Conf, $Me, $Error, $OK;
	$ajax = defval($_REQUEST, "ajax", false);
	if ($Me->canSetOutcome($prow)) {
	    $o = rcvtint($_REQUEST["decision"]);
	    $rf = reviewForm();
	    if (isset($rf->options["outcome"][$o])) {
		$result = $Conf->qe("update Paper set outcome=$o where paperId=$prow->paperId", "while changing decision");
		if ($result && $ajax)
		    $Conf->confirmMsg("Saved");
		else if ($result)
		    $Conf->confirmMsg("Decision for paper #$prow->paperId set to " . htmlspecialchars($rf->options["outcome"][$o]) . ".");
		if ($o > 0 || $prow->outcome > 0)
		    $Conf->updatePaperaccSetting($o > 0);
	    } else {
		$Conf->errorMsg("Bad decision value.");
		$Error["decision"] = true;
	    }
	} else
	    $Conf->errorMsg("You can't set the decision for paper #$prow->paperId." . ($Me->privChair ? "  (<a href=\"" . htmlspecialchars(selfHref(array("forceShow" => 1))) . "\">Override conflict</a>)" : ""));
	if ($ajax)
	    $Conf->ajaxExit(array("ok" => $OK && !defval($Error, "decision")));
    }

    function setReviewPreference($prow) {
	global $Conf, $Me, $Error, $OK;
	$ajax = defval($_REQUEST, "ajax", false);
	if (!$Me->privChair
	    || ($contactId = rcvtint($_REQUEST["contactId"])) <= 0)
	    $contactId = $Me->contactId;
	if (($v = cvtpref($_REQUEST['revpref'])) >= -1000000) {
	    $while = "while saving review preference";
	    $Conf->qe("lock tables PaperReviewPreference write", $while);
	    $Conf->qe("delete from PaperReviewPreference where contactId=$contactId and paperId=$prow->paperId", $while);
	    $result = $Conf->qe("insert into PaperReviewPreference (paperId, contactId, preference) values ($prow->paperId, $contactId, $v)", $while);
	    $Conf->qe("unlock tables", $while);
	    if ($result)
		$Conf->confirmMsg($ajax ? "Saved" : "Review preference saved.");
	    else
		$Error["revpref"] = true;
	} else {
	    $Conf->errorMsg($ajax ? "Preferences must be small positive or negative integers." : "Preferences must be small integers.  0 means don't care; positive numbers mean you want to review a paper, negative numbers mean you don't.  The greater the absolute value, the stronger your feelings.");
	    $Error["revpref"] = true;
	}
	if ($ajax)
	    $Conf->ajaxExit(array("ok" => $OK && !defval($Error, "revpref")));
    }

    function setLeadOrShepherd($prow, $type, $ajaxexit = true) {
        global $Conf, $Me, $Error, $OK;
	$ajax = defval($_REQUEST, "ajax", false);
	if (!$Me->actChair($prow)) {
	    $Conf->errorMsg("You don't have permission to set the $type.");
	    $Error[$type] = true;
	} else if (isset($_REQUEST[$type])
		   && ($_REQUEST[$type] === "0"
		       || ($pc = pcByEmail($_REQUEST[$type])))) {
	    $contactId = ($_REQUEST[$type] === "0" ? 0 : $pc->contactId);
	    $field = $type . "ContactId";
	    if ($contactId != $prow->$field) {
		$Conf->qe("update Paper set $field=$contactId where paperId=$prow->paperId", "while updating $type");
		if (!$Conf->setting("paperlead")) {
		    $Conf->qe("insert into Settings (name, value) values ('paperlead', 1) on duplicate key update value=1");
		    $Conf->updateSettings();
		}
		if ($OK)
		    $Conf->log("set $type to " . $_REQUEST[$type], $Me, $prow->paperId);
	    }
	    if ($OK && $ajax)
		$Conf->confirmMsg("Saved");
	} else {
	    $Conf->errorMsg("Bad $type setting &ldquo;" . htmlspecialchars(defval($_REQUEST, $type, "")) . "&rdquo;.");
	    $Error[$type] = true;
	}
	if ($ajax && $ajaxexit)
	    $Conf->ajaxExit(array("ok" => $OK && !defval($Error, $type)));
    }

    function setTags($prow) {
	global $Conf, $Me, $Error, $OK, $forceShow;
	$ajax = defval($_REQUEST, "ajax", false);
        if ($Me->canSetTags($prow, $Conf, $forceShow)) {
	    require_once("Code/tags.inc");
	    setTags($prow->paperId, defval($_REQUEST, "tags", ""), 'p', $Me->privChair);
	} else {
	    $Conf->errorMsg("You cannot set tags for paper #$prow->paperId." . ($Me->privChair ? "  (<a href=\"" . htmlspecialchars(selfHref(array("forceShow" => 1))) . "\">Override conflict</a>)" : ""));
	    $Error["tags"] = true;
	}
	if ($ajax)
	    $Conf->ajaxExit(array("ok" => $OK && !defval($Error, "tags")));
    }

    function tagReport($prow) {
	global $Conf, $ConfSiteSuffix, $Me, $Error, $OK, $forceShow;
	$ajax = defval($_REQUEST, "ajax", false);
	if ($Me->canViewTags($prow, $Conf, $forceShow)) {
	    require_once("Code/tags.inc");
	    $vt = voteTags();
	    if (count($vt) > 0) {
		$q = "";
		$mytagprefix = $Me->contactId . "~";
		foreach ($vt as $tag => $v)
		    $q .= ($q === "" ? "" : ", ") . "'$mytagprefix" . sqlq($tag) . "'";
		$result = $Conf->qe("select tag, sum(tagIndex) from PaperTag where tag in ($q) group by tag", "while finding vote tag totals");
		while (($row = edb_row($result)))
		    $vt[substr($row[0], strlen($mytagprefix))] -= $row[1];
		$r = "";
		ksort($vt);
		foreach ($vt as $tag => $v)
		    if (max($v, 0) > 0)
			$r .= ($r === "" ? "" : ", ") . "<a class='q' href=\"search$ConfSiteSuffix?q=rorder:~$tag&amp;showtags=1\">~$tag</a>#" . max($v, 0);
		if ($r !== "")
		    $Conf->confirmMsg("Unallocated <a href='help$ConfSiteSuffix?t=votetags'>votes</a>: $r");
	    }
	} else {
	    $Conf->errorMsg("You can't view tags for paper #$prow->paperId.");
	    $Error["tags"] = true;
	}
	if ($ajax)
	    $Conf->ajaxExit(array("ok" => $OK && !defval($Error, "tags")), true);
    }

}