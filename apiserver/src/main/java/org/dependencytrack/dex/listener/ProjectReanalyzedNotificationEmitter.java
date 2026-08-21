/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.dex.listener;

import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEvent;
import org.dependencytrack.dex.engine.api.event.WorkflowRunsCompletedEventListener;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.proto.v1.Notification;
import org.dependencytrack.notification.proto.v1.Project;
import org.dependencytrack.persistence.jdbi.NotificationSubjectDao;
import org.dependencytrack.vulnanalysis.VulnAnalysisWorkflow;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import static org.dependencytrack.dex.DexWorkflowLabels.WF_LABEL_PROJECT_UUID;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectReanalyzedFailedNotification;
import static org.dependencytrack.notification.api.NotificationFactory.createProjectReanalyzedNotification;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * A {@link WorkflowRunsCompletedEventListener} that emits {@code PROJECT_REANALYZED} and
 * {@code PROJECT_REANALYZED_FAILED} notifications upon completion of {@link VulnAnalysisWorkflow} runs.
 * <p>
 * ORBIK: reimplements, on top of the 5.x Dex workflow engine, the notifications that the 4.x fork
 * dispatched from {@code VulnerabilityAnalysisTask}'s try/catch around project reanalysis (fork
 * commit 16279b241). The engine only reports terminal {@link WorkflowRunStatus} here, not the
 * underlying exception, so the FAILED cause is coarser than in 4.x: it names the workflow's
 * terminal status, not the original exception message. The exception itself still reaches the
 * application logs, MDC-tagged with the project UUID, so it stays correlatable even though it is
 * not embedded in the notification.
 *
 * @since 5.0.4-orbik
 */
public final class ProjectReanalyzedNotificationEmitter implements WorkflowRunsCompletedEventListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ProjectReanalyzedNotificationEmitter.class);

    @Override
    public void onEvent(WorkflowRunsCompletedEvent event) {
        final var relevantRuns = new ArrayList<RelevantRun>();

        for (final WorkflowRunMetadata runMetadata : event.completedRuns()) {
            if (!"vuln-analysis".equals(runMetadata.workflowName())) {
                continue;
            }

            final Map<String, String> labels = runMetadata.labels();
            if (labels == null) {
                continue;
            }

            final UUID projectUuid = Optional
                    .ofNullable(labels.get(WF_LABEL_PROJECT_UUID))
                    .map(UUID::fromString)
                    .orElse(null);
            if (projectUuid != null) {
                relevantRuns.add(new RelevantRun(projectUuid, runMetadata.status()));
            }
        }

        if (relevantRuns.isEmpty()) {
            return;
        }

        final Set<UUID> projectUuids = relevantRuns.stream()
                .map(RelevantRun::projectUuid)
                .collect(Collectors.toSet());

        final Map<UUID, Project> projectByUuid = withJdbiHandle(
                handle -> handle
                        .attach(NotificationSubjectDao.class)
                        .getProjects(projectUuids)
                        .stream()
                        .collect(Collectors.toMap(
                                project -> UUID.fromString(project.getUuid()),
                                Function.identity())));

        final var notifications = new ArrayList<Notification>(relevantRuns.size());
        for (final RelevantRun run : relevantRuns) {
            final Project project = projectByUuid.get(run.projectUuid());
            if (project == null) {
                continue;
            }

            if (run.status() == WorkflowRunStatus.COMPLETED) {
                notifications.add(createProjectReanalyzedNotification(project));
            } else {
                notifications.add(createProjectReanalyzedFailedNotification(
                        project,
                        "Vulnerability analysis workflow ended with status " + run.status()));
            }
        }

        LOGGER.debug("Emitting {} PROJECT_REANALYZED / PROJECT_REANALYZED_FAILED notifications", notifications.size());
        useJdbiTransaction(handle -> new JdbiNotificationEmitter(handle).emitAll(notifications));
    }

    private record RelevantRun(
            UUID projectUuid,
            WorkflowRunStatus status) {
    }

}
