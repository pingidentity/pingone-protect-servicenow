(function process(/*RESTAPIRequest*/ request, /*RESTAPIResponse*/ response) {

    function getSignal(signal) {

        if (!signal) {
            return "";
        }

        var lines = [];

        if (signal.level) {
            lines.push("  Level: " + signal.level);
        }

        if (signal.status) {
            lines.push("  Status: " + signal.status);
        }

        if (signal.reason) {
            lines.push("  Reason: " + signal.reason);
        }

        if (signal.type) {
            lines.push("  Type: " + signal.type);
        }

        return "\n" + lines.join("\n");
    }

    function getVelocitySignal(signal) {

        if (!signal) {
            return "";
        }

        var velocity = signal.velocity || {};
        var threshold = signal.threshold || {};
        var lines = [];

        if (signal.level) {
            lines.push("  Level: " + signal.level);
        }

        if (velocity.distinctCount !== undefined) {
            lines.push("  Distinct count: " + velocity.distinctCount);
        }

        if (velocity.during !== undefined) {
            lines.push("  During seconds: " + velocity.during);
        }

        if (threshold.source) {
            lines.push("  Threshold source: " + threshold.source);
        }

        return "\n" + lines.join("\n");
    }

    var payload = null;

    try {
        payload = request.body.data;
    } catch (e) {
        payload = null;
    }

    if (!payload) {
        try {
            payload = JSON.parse(request.body.dataString);
        } catch (ex) {
            payload = {};
        }
    }

    var events = [];

    if (Array.isArray(payload)) {
        events = payload;
    } else if (payload && payload.action) {
        events = [payload];
    }

    var created = [];

    for (var i = 0; i < events.length; i++) {

        var evt = events[i] || {};

        var action = evt.action || {};
        var embedded = evt._embedded || {};
        var riskEvaluation = embedded.riskEvaluation || {};
        var riskEvaluationResult = riskEvaluation.result || {};
        var riskEvent = embedded.riskEvent || {};
        var riskDetails = riskEvaluation.details || {};

        var actionType = (
            action.type ||
            evt.type ||
            evt.eventType ||
            ""
        ).toString().toUpperCase();

        if (actionType !== "RISK_EVALUATION.CREATED") {
            continue;
        }

        var riskLevel = (
            riskEvaluationResult.level ||
            ""
        ).toString().toUpperCase();

        if (riskLevel !== "HIGH") {
            continue;
        }

        var riskScore = riskEvaluationResult.score || "";
        var eventId = (evt.id || "").toString();
        var recordedAt = (evt.recordedAt || "").toString();

        var userName =
            riskEvent.username ||
            (riskEvaluation.event &&
             riskEvaluation.event.user &&
             riskEvaluation.event.user.name) ||
            (evt.actors &&
             evt.actors.user &&
             evt.actors.user.name) ||
            "";

        var ipAddress =
            riskEvent.ip ||
            (riskEvaluation.event && riskEvaluation.event.ip) ||
            (evt.source && evt.source.ipAddress) ||
            "";

        var callerSysId = "";

        if (userName) {

            var caller = new GlideRecord("sys_user");
            caller.addQuery("email", userName);
            caller.query();

            if (caller.next()) {
                callerSysId = caller.getUniqueValue();
            }
        }

        var assignmentGroupSysId = "";

        var assignmentGroup = new GlideRecord("sys_user_group");
        assignmentGroup.addQuery("name", "Fraud Analysts");
        assignmentGroup.query();

        if (assignmentGroup.next()) {
            assignmentGroupSysId = assignmentGroup.getUniqueValue();
        }

        var ipRepDomain =
            riskDetails.ipAddressReputation &&
            riskDetails.ipAddressReputation.domain ||
            {};

        var device = riskDetails.device || {};
        var deviceOs = device.os || {};
        var deviceBrowser = device.browser || {};

        var inc = new GlideRecord("incident");
        inc.initialize();

        if (callerSysId) {
            inc.caller_id = callerSysId;
        }

        if (assignmentGroupSysId) {
            inc.assignment_group = assignmentGroupSysId;
        }

        inc.short_description =
            "PingOne Protect HIGH Risk Evaluation";

        inc.description =

            "PingOne Protect HIGH risk evaluation detected.\n\n" +

            "Recorded at: " + recordedAt + "\n" +
            "Risk level: " + riskLevel + "\n" +
            "Risk score: " + riskScore + "\n" +
            "User: " + userName + "\n" +
            "IP address: " + ipAddress + "\n" +
            "Event ID: " + eventId + "\n\n" +

            "Location\n" +
            "Country: " + (riskDetails.country || "") + "\n" +
            "State: " + (riskDetails.state || "") + "\n" +
            "City: " + (riskDetails.city || "") + "\n\n" +

            "Device\n" +
            "Device ID: " + (device.id || "") + "\n" +
            "Mobile device: " + device.isMobile + "\n" +
            "Estimated distance: " + device.estimatedDistance + "\n" +
            "OS: " + (deviceOs.name || "") + "\n" +
            "Browser: " + (deviceBrowser.name || "") + "\n\n" +

            "Network\n" +
            "Anonymous network detected: " + riskDetails.anonymousNetworkDetected + "\n" +
            "Impossible travel: " + riskDetails.impossibleTravel + "\n" +
            "ASN: " + (ipRepDomain.asn || "") + "\n" +
            "Organization: " + (ipRepDomain.organization || "") + "\n" +
            "ISP: " + (ipRepDomain.isp || "") + "\n\n" +

            "Risk Signals\n\n" +

            "New device:" +
            getSignal(riskDetails.newDevice) + "\n\n" +

            "Anonymous network:" +
            getSignal(riskDetails.anonymousNetwork) + "\n\n" +

            "IP risk:" +
            getSignal(riskDetails.ipRisk) + "\n\n" +

            "Adversary in the middle:" +
            getSignal(riskDetails.adversaryInTheMiddle) + "\n\n" +

            "Traffic anomaly:" +
            getSignal(riskDetails.trafficAnomaly) + "\n\n" +

            "Suspicious device:" +
            getSignal(riskDetails.suspiciousDevice) + "\n\n" +

            "User location anomaly:" +
            getSignal(riskDetails.userLocationAnomaly) + "\n\n" +

            "Geo velocity:" +
            getSignal(riskDetails.geoVelocity) + "\n\n" +

            "Bot detection:" +
            getSignal(riskDetails.botDetection) + "\n\n" +

            "User based risk behavior:" +
            getSignal(riskDetails.userBasedRiskBehavior) + "\n\n" +

            "IP velocity by user:" +
            getVelocitySignal(riskDetails.ipVelocityByUser) + "\n\n" +

            "User velocity by IP:" +
            getVelocitySignal(riskDetails.userVelocityByIp);

        inc.category = "security";
        inc.impact = 1;
        inc.urgency = 1;

        var incidentId = inc.insert();
        created.push(incidentId);
    }

    response.setStatus(200);
    response.setHeader("Content-Type", "application/json");

    response.setBody({
        status: "success",
        received_count: events.length,
        created_count: created.length,
        incidents: created
    });

})(request, response);
