<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>

<jsp:include page="header.jsp">
    <jsp:param name="pageTitle" value="PowerAuth - Activation Details"/>
</jsp:include>

<ol class="breadcrumb">
    <li><a class="black" href="${pageContext.request.contextPath}/activation/list">User Selection</a></li>
    <li><a class="black" href="${pageContext.request.contextPath}/activation/list?userId=<c:out value="${userId}"/>">User "<c:out value="${userId}"/>"</a></li>
    <li class="active">Activation Detail</li>
</ol>

<div class="row">
    <div class="col-md-4">

        <c:if test="${status == 'CREATED'}">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title pull-left">New Client Activation</h3>
                    <a href=""><span class="glyphicon glyphicon-refresh black pull-right"></span></a>
                    <div class="clearfix"></div>
                </div>
                <div class="panel-body gray">
                    <div>
                        Client Activation Code<br/>
                        <div class="input-group">
                            <input id="activation-code" type="text" class="form-control" readonly="readonly" value="<c:out value="${activationCode}"/>">
                            <span class="input-group-btn">
                                <button class="btn btn-default btn-clipboard" type="button" data-clipboard-text="<c:out value="${activationCode}"/>">
                                    <span class=" glyphicon glyphicon-copy"></span>
                                </button>
                            </span>
                        </div>
                    </div>
                    <p>
                        Client Activation Code Signature<br>
                        <strong class="code black wrap"><c:out value="${activationSignature}"/></strong>
                    </p>
                    <p>
                        <img src="<c:out value="${activationQR}"/>" class="w100" alt="Activation QR Code" style="border: 1px solid #777777"/>
                    </p>
                </div>
            </div>
        </c:if>

        <c:if test="${status == 'PENDING_COMMIT'}">
            <div class="panel panel-default">
                <div class="panel-heading">
                    <h3 class="panel-title">Activation Verification</h3>
                </div>
                <div class="panel-body gray">
                    <div>
                        Device Public Key Fingerprint<br/>
                        <div class="input-group">
                            <input id="activation-fingerprint" type="text" class="form-control" readonly="readonly" value="<c:out value="${activationFingerprint}"/>"/>
                            <span class="input-group-btn">
                                <button class="btn btn-default btn-clipboard" type="button" data-clipboard-text="<c:out value="${activationFingerprint}"/>">
                                    <span class=" glyphicon glyphicon-copy"></span>
                                </button>
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </c:if>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">Basic Activation Information</h3>
            </div>
            <div class="panel-body gray">
                <div>
                    Activation ID<br>
                    <div class="input-group">
                        <input type="text" class="form-control code black" readonly="readonly" value="<c:out value="${activationId}"/>"/>
                        <span class="input-group-btn">
                            <button class="btn btn-default btn-clipboard" type="button" data-clipboard-text="<c:out value="${activationId}"/>">
                                <span class=" glyphicon glyphicon-copy"></span>
                            </button>
                        </span>
                    </div>
                </div>
                <table class="w100">
                    <tr>
                        <c:if test="${activationName != null}">
                        <td>
                            <p>
                                Activation Name<br>
                                <span class="black"><c:out value="${activationName}"/></span>
                            </p>
                        </td>
                        </c:if>
                        <td>
                            <p>
                                Version<br>
                                <span class="black">
                                    <c:choose>
                                        <c:when test="${version != 0}">
                                            <c:out value="${version}"/>
                                        </c:when>
                                        <c:otherwise>
                                            Unknown
                                        </c:otherwise>
                                    </c:choose>
                                </span>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>
                                Created<br>
                                <span class="black">
                                    <fmt:formatDate type="both" pattern="yyyy/MM/dd HH:mm:ss" value="${timestampCreated.toGregorianCalendar().time}"/>
                                </span>
                            </p>
                        </td>
                        <td>
                            <p>
                                Last Used<br>
                                <span class="black">
                                    <fmt:formatDate type="both" pattern="yyyy/MM/dd HH:mm:ss" value="${timestampLastUsed.toGregorianCalendar().time}"/>
                                </span>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <td>
                            <p>
                                Application<br>
                                <span class="black">
                                    <a class="black" href="${pageContext.request.contextPath}/application/detail/<c:out value="${applicationId}"/>">
                                        <c:out value="${applicationId}"/>
                                    </a>
                                </span>
                            </p>
                        </td>
                        <td>
                            <p>
                                Status<br>
                                <jsp:include page="activationStatusSnippet.jsp">
                                    <jsp:param value="${status}" name="status"/>
                                </jsp:include>
                            </p>
                        </td>
                    </tr>
                        <tr>
                            <c:if test="${platform != null}">
                            <td>
                                Platform<br>
                                <c:choose>
                                    <c:when test="${platform == 'ios'}">
                                        <span class="black">iOS</span>
                                    </c:when>
                                    <c:when test="${platform == 'android'}">
                                        <span class="black">Android</span>
                                    </c:when>
                                    <c:when test="${platform == 'hw'}">
                                        <span class="black">Hardware Token</span>
                                    </c:when>
                                    <c:when test="${platform == 'unknown'}">
                                        <span class="black">Unknown</span>
                                    </c:when>
                                    <c:otherwise>
                                        <span class="black">${platform}</span>
                                    </c:otherwise>
                                </c:choose>
                            </td>
                            </c:if>
                            <c:if test="${deviceInfo != null}">
                            <td>
                                User Device Information<br>
                                <span class="black">
                                    <c:out value="${deviceInfo}"/>
                                </span>
                            </td>
                            </c:if>
                        </tr>
                    <c:if test="${not empty blockedReason}">
                        <tr>
                            <td colspan="2">
                                Blocked Reason<br>
                                <span class="orange code">
                                    <c:out value="${blockedReason}"/>
                                </span>
                            </td>
                        </tr>
                    </c:if>
                </table>
            </div>
            <c:if test="${status != 'REMOVED'}">
                <div class="panel-footer">
                    <jsp:include page="activationStatusForms.jsp">
                        <jsp:param value="${status}" name="status"/>
                        <jsp:param value="${activationId}" name="activationId"/>
                        <jsp:param value="${showOtpInput}" name="showOtpInput"/>
                        <jsp:param value="${error}" name="error"/>
                    </jsp:include>
                </div>
            </c:if>
        </div>

        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title button-sm pull-left">Activation Flags</h3>
                <a href="${pageContext.request.contextPath}/activation/detail/${activationId}/flag/create" class="btn btn-sm btn-default pull-right">Add Flag</a>
                <div class="clearfix"></div>
            </div>
            <c:choose>
                <c:when test="${fn:length(activationFlags) == 0}">
                    <div class="panel-body">
                        <p class="gray text-center">
                            No activation flags are configured
                        </p>
                    </div>
                </c:when>
                <c:otherwise>
                    <table class="table table-hover">
                        <thead>
                        <tr>
                            <th>Name</th>
                            <th>&nbsp;</th>
                        </tr>
                        </thead>
                        <tbody>
                        <c:forEach items="${activationFlags}" var="item">
                            <tr class="code">
                                <td><c:out value="${item}"/></td>
                                <td>
                                    <form action="${pageContext.request.contextPath}/activation/detail/${activationId}/flag/remove/do.submit" method="POST" class="action-remove">
                                        <input type="hidden" name="name" value="${item}"/>
                                        <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                        <input type="submit" value="Remove" class="btn btn-sm btn-danger pull-right btn-table"/>
                                    </form>
                                </td>
                            </tr>
                        </c:forEach>
                        </tbody>
                    </table>
                </c:otherwise>
            </c:choose>
        </div>

        <c:if test="${not empty recoveryCodes}">
            <c:forEach items="${recoveryCodes}" var="item">
                <div class="panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Recovery Code</h3>
                    </div>
                    <div class="panel-body gray">
                        <table class="w100">
                            <tr>
                                <td>
                                    <p>
                                        Activation Code<br>
                                        <span class="black"><c:out value="${item.recoveryCodeMasked}"/></span>
                                    </p>
                                </td>
                                <td>
                                    <p>
                                        Status<br>
                                        <jsp:include page="recoveryCodeStatusSnippet.jsp">
                                            <jsp:param value="${item.status}" name="status"/>
                                        </jsp:include>
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </div>
                    <c:if test="${item.status != 'REVOKED'}">
                        <div class="panel-footer">
                            <form action="${pageContext.request.contextPath}/activation/recovery/revoke/do.submit"
                                  method="POST" class="pull-right action-revoke">
                                    <input type="hidden" name="activationId" value="<c:out value="${item.activationId}"/>"/>
                                    <input type="hidden" name="recoveryCodeId" value="<c:out value="${item.recoveryCodeId}"/>"/>
                                    <input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}"/>
                                    <input type="submit" value="Revoke" class="btn btn-danger"/>
                            </form>
                            <div class="clearfix"></div>
                        </div>
                    </c:if>
                </div>
            </c:forEach>
        </c:if>
    </div>

    <div class="col-md-8">
        <div id="panel-with-tabs" class="panel panel-default">
            <div class="panel-body">
                <form method="get" action="${pageContext.request.contextPath}/activation/detail/${activationId}" class="form-inline">
                    <div class="input-group w100">
                        <span class="input-group-addon">From</span>
                        <input type="text" name="fromDate" class="form-control" placeholder="yyyy/MM/dd HH:mm:ss" value="<c:out value="${fromDate}"/>"/>
                        <span class="input-group-addon">To</span>
                        <input type="text" name="toDate" class="form-control" placeholder="yyyy/DD/dd HH:mm:ss" value="<c:out value="${toDate}"/>"/>
                        <span class="input-group-btn">
                            <input type="submit" class="btn btn-default w100" value="Filter" />
                        </span>
                    </div>
                </form>
            </div>
            <ul class="nav nav-tabs" id="nav-tab" role="tablist">
                <li role="presentation"><a href="#signatures" id="tabs-signatures" aria-controls="signatures" role="tab" data-toggle="tab">Last Signatures</a></li>
                <li role="presentation"><a href="#history" id="tabs-history" aria-controls="history" role="tab" data-toggle="tab">Activation Changes</a></li>
            </ul>
            <div id="tab-content" class="tab-content">
                <div role="tabpanel" class="tab-pane" id="signatures" aria-labelledby="tabs-signatures">
                    <table class="table w100">
                        <tbody>
                        <c:choose>
                            <c:when test="${fn:length(signatures) == 0}">
                                <tr class="code gray text-center">
                                    <td colspan="4">
                                        <p class="padder20">No signatures in the selected interval</p>
                                    </td>
                                </tr>
                            </c:when>
                            <c:otherwise>
                                <c:forEach items="${signatures}" var="item">
                                    <tr class="code">
                                        <td class="gray" style="width: 270px;">
                                            <p>
                                                Transaction ID<br>
                                                <span class="black"><c:out value="${item.id}"/></span>
                                            </p>
                                            <p>
                                                Date<br>
                                                <span class="black">
                                                    <fmt:formatDate type="both" pattern="yyyy/MM/dd HH:mm:ss" value="${item.timestampCreated}"/>
                                                </span>
                                            </p>
                                            <p>
                                                Value<br>
                                                <span class="black"><c:out value="${item.signature}"/></span>
                                            </p>
                                            <p>
                                                Type<br>
                                                <span class="black"><c:out value="${item.signatureType}"/></span>
                                            </p>
                                            <p>
                                                Result<br>
                                                <span class="black">
                                                    <c:choose>
                                                        <c:when test="${item.valid}"><span class="green">OK</span>:</c:when>
                                                        <c:otherwise><span class="red">NOK</span>:</c:otherwise>
                                                    </c:choose>
                                                    <c:out value="${item.note}"/>
                                                </span>
                                            </p>
                                            <table class="w100">
                                                <tr>
                                                    <td>
                                                        Activation<br>
                                                        <span class="black">
                                                            <jsp:include page="activationStatusSnippet.jsp">
                                                                <jsp:param value="${item.activationStatus}" name="status"/>
                                                            </jsp:include>
                                                        </span>
                                                    </td>
                                                    <td>
                                                        Counter<br>
                                                        <span class="black"><c:out value="${item.activationCounter}"/></span>
                                                    </td>
                                                    <td>
                                                        Version<br>
                                                        <span class="black">
                                                            <c:choose>
                                                                <c:when test="${not empty item.signatureVersion}">
                                                                    <c:out value="${item.version}"/> (<c:out value="${item.signatureVersion}"/>)
                                                                </c:when>
                                                                <c:otherwise>
                                                                    <c:out value="${item.version}"/>
                                                                </c:otherwise>
                                                            </c:choose>
                                                        </span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                        <td>
                                            <p class="wrap gray">
                                                Signed Data
                                                <c:choose>
                                                    <c:when test="${not empty item.signatureData}">
                                                        <span class="glyphicon glyphicon-zoom-in" data-toggle="tooltip" data-html="true" data-placement="top" title="<table><tr><td>Request&nbsp;method:&nbsp;&nbsp;&nbsp;</td><td><c:out value="${item.signatureData.requestMethod}"/></td></tr><tr><td>Request&nbsp;URI:</td><td><c:out value="${item.signatureData.requestURIIdentifier}"/></td></tr><tr><td>Request&nbsp;body:</td><td><span class='word-break'><c:out value="${item.signatureData.requestBody}"/></span></td></tr></table>"></span>
                                                    </c:when>
                                                    <c:otherwise>
                                                        <span class="glyphicon glyphicon-zoom-in" data-toggle="tooltip" data-html="true" data-placement="top" title="Unrecognized signature data"></span>
                                                    </c:otherwise>
                                                </c:choose>
                                                <br/>
                                                <span class="black">
                                                    <c:out value="${item.data}"/>
                                                </span>
                                            </p>
                                            <c:if test="${not empty item.additionalInfo.entry}">
                                                <p class="wrap gray">
                                                    Additional Information<br>
                                                    <c:forEach var="entry" items="${item.additionalInfo.entry}">
                                                        <span class="black">
                                                            <c:out value="${entry.key}"/>: <c:out value="${entry.value}"/>
                                                        </span>
                                                        <br/>
                                                    </c:forEach>
                                                </p>
                                            </c:if>
                                        </td>
                                    </tr>
                                </c:forEach>
                            </c:otherwise>
                        </c:choose>
                        </tbody>
                    </table>
                </div>
                <div role="tabpanel" class="tab-pane" id="history" aria-labelledby="tabs-history">
                    <table class="table w100">
                        <tbody>
                        <c:choose>
                            <c:when test="${fn:length(history) == 0}">
                                <tr class="code gray text-center">
                                    <td colspan="4">
                                        <p class="padder20">No changes in the selected interval</p>
                                    </td>
                                </tr>
                            </c:when>
                            <c:otherwise>
                                <c:forEach items="${history}" var="item">
                                    <tr class="code">
                                        <td class="gray" style="width: 270px;">
                                            <p>
                                                Change ID<br>
                                                <span class="black"><c:out value="${item.id}"/></span>
                                            </p>
                                            <p>
                                                Date<br>
                                                <span class="black">
                                                    <fmt:formatDate type="both" pattern="yyyy/MM/dd HH:mm:ss" value="${item.timestampCreated.toGregorianCalendar().time}"/>
                                                </span>
                                            </p>
                                        </td>
                                        <td>
                                            <p>
                                                Status<br>
                                                <span class="black">
                                                    <jsp:include page="activationStatusSnippet.jsp">
                                                        <jsp:param value="${item.activationStatus}" name="status"/>
                                                    </jsp:include>
                                                </span>
                                            </p>
                                        </td>
                                        <c:choose>
                                            <c:when test="${not empty item.eventReason}">
                                                <td>
                                                    <c:choose>
                                                        <c:when test="${item.activationStatus == 'BLOCKED'}">
                                                            Blocked Reason
                                                        </c:when>
                                                        <c:otherwise>
                                                            Event Reason
                                                        </c:otherwise>
                                                    </c:choose>
                                                    <br>
                                                    <span class="orange code">
                                                        <c:out value="${item.eventReason}"/>
                                                    </span>
                                                </td>
                                            </c:when>
                                            <c:otherwise>
                                                <td>
                                                    &nbsp;
                                                </td>
                                            </c:otherwise>
                                        </c:choose>
                                        <c:choose>
                                            <c:when test="${not empty item.externalUserId}">
                                                <td>
                                                    Changed By<br>
                                                    <span class="orange code">
                                                        <c:out value="${item.externalUserId}"/>
                                                    </span>
                                                </td>
                                            </c:when>
                                            <c:otherwise>
                                                <td>
                                                    &nbsp;
                                                </td>
                                            </c:otherwise>
                                        </c:choose>
                                    </tr>
                                </c:forEach>
                            </c:otherwise>
                        </c:choose>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

</div>

<jsp:include page="footer.jsp"/>


<script type="text/javascript">
    $(document).ready(function () {
        // Disable HTML sanitizer for signature data tooltip
        const whiteList = $.fn.tooltip.Constructor.DEFAULTS.whiteList;
        whiteList.table = [];
        whiteList.tr = [];
        whiteList.td = [];
        whiteList.tbody = [];
        whiteList.thead = [];
        whiteList.span = ['class'];
        // Choose tab by location hash
        if (!window.location.hash) {
            $('a[href="#signatures"]').tab('show');
        } else {
            $('a[href="'+window.location.hash+'"]').tab('show');
        }
        // Change location hash on click
        $('.nav-tabs a').on('shown.bs.tab', function (e) {
            if (history.pushState) {
                history.pushState(null, null, e.target.hash);
            } else {
                window.location.hash = e.target.hash;
            }
        });
    });
</script>