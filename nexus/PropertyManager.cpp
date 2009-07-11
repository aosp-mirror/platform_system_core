/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "PropertyManager"

#include <cutils/log.h>

#include "PropertyManager.h"

PropertyManager::PropertyManager() {
    mNamespaces = new PropertyNamespaceCollection();
    pthread_mutex_init(&mLock, NULL);
}

PropertyManager::~PropertyManager() {
    PropertyNamespaceCollection::iterator it;

    for (it = mNamespaces->begin(); it != mNamespaces->end();) {
        delete (*it);
        it = mNamespaces->erase(it);
    }
    delete mNamespaces;
}

PropertyNamespace *PropertyManager::lookupNamespace_UNLOCKED(const char *ns) {
    PropertyNamespaceCollection::iterator ns_it;

    for (ns_it = mNamespaces->begin(); ns_it != mNamespaces->end(); ++ns_it) {
        if (!strcasecmp(ns, (*ns_it)->getName()))
            return (*ns_it);
    }
    errno = ENOENT;
    return NULL;
}

Property *PropertyManager::lookupProperty_UNLOCKED(PropertyNamespace *ns, const char *name) {
    PropertyCollection::iterator it;

    for (it = ns->getProperties()->begin();
         it != ns->getProperties()->end(); ++it) {
        if (!strcasecmp(name, (*it)->getName()))
            return (*it);
    }
    errno = ENOENT;
    return NULL;
}

int PropertyManager::attachProperty(const char *ns_name, Property *p) {
    PropertyNamespace *ns;

    LOGD("Attaching property %s to namespace %s", p->getName(), ns_name);
    pthread_mutex_lock(&mLock);
    if (!(ns = lookupNamespace_UNLOCKED(ns_name))) {
        LOGD("Creating namespace %s", ns_name);
        ns = new PropertyNamespace(ns_name);
        mNamespaces->push_back(ns);
    }

    if (lookupProperty_UNLOCKED(ns, p->getName())) {
        errno = EADDRINUSE;
        pthread_mutex_unlock(&mLock);
        LOGE("Failed to register property %s.%s (%s)",
            ns_name, p->getName(), strerror(errno));
        return -1;
    }

    ns->getProperties()->push_back(p);
    pthread_mutex_unlock(&mLock);
    return 0;
}

int PropertyManager::detachProperty(const char *ns_name, Property *p) {
    PropertyNamespace *ns;

    LOGD("Detaching property %s from namespace %s", p->getName(), ns_name);
    pthread_mutex_lock(&mLock);
    if (!(ns = lookupNamespace_UNLOCKED(ns_name))) {
        pthread_mutex_unlock(&mLock);
        LOGE("Namespace '%s' not found", ns_name);
        return -1;
    }

    PropertyCollection::iterator it;

    for (it = ns->getProperties()->begin();
         it != ns->getProperties()->end(); ++it) {
        if (!strcasecmp(p->getName(), (*it)->getName())) {
            delete ((*it));
            ns->getProperties()->erase(it);
            pthread_mutex_unlock(&mLock);
            return 0;
        }
    }

    LOGE("Property %s.%s not found", ns_name, p->getName());
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return -1;
}

int PropertyManager::doSet(Property *p, int idx, const char *value) {

    if (p->getReadOnly()) {
        errno = EROFS;
        return -1;
    }

    if (p->getType() == Property::Type_STRING) {
        return p->set(idx, value);
    } else if (p->getType() == Property::Type_INTEGER) {
        int tmp;
        errno = 0;
        tmp = strtol(value, (char **) NULL, 10);
        if (errno) {
            LOGE("Failed to convert '%s' to int", value);
            errno = EINVAL;
            return -1;
        }
        return p->set(idx, tmp);
    } else if (p->getType() == Property::Type_IPV4) {
        struct in_addr tmp;
        if (!inet_aton(value, &tmp)) {
            LOGE("Failed to convert '%s' to ipv4", value);
            errno = EINVAL;
            return -1;
        }
        return p->set(idx, &tmp);
    } else {
        LOGE("Property '%s' has an unknown type (%d)", p->getName(),
             p->getType());
        errno = EINVAL;
        return -1;
    }
    errno = ENOENT;
    return -1;
}

int PropertyManager::doGet(Property *p, int idx, char *buffer, size_t max) {

    if (p->getType() == Property::Type_STRING) {
        if (p->get(idx, buffer, max)) {
            LOGW("String property %s get failed (%s)", p->getName(),
                 strerror(errno));
            return -1;
        }
    }
    else if (p->getType() == Property::Type_INTEGER) {
        int tmp;
        if (p->get(idx, &tmp)) {
            LOGW("Integer property %s get failed (%s)", p->getName(),
                 strerror(errno));
            return -1;
        }
        snprintf(buffer, max, "%d", tmp);
    } else if (p->getType() == Property::Type_IPV4) {
        struct in_addr tmp;
        if (p->get(idx, &tmp)) {
            LOGW("IPV4 property %s get failed (%s)", p->getName(),
                 strerror(errno));
            return -1;
        }
        strncpy(buffer, inet_ntoa(tmp), max);
    } else {
        LOGE("Property '%s' has an unknown type (%d)", p->getName(),
             p->getType());
        errno = EINVAL;
        return -1;
    }
    return 0;
}

/*
 * IPropertyManager methods
 */

int PropertyManager::set(const char *name, const char *value) {

    LOGD("set %s = '%s'", name, value);
    pthread_mutex_lock(&mLock);
    PropertyNamespaceCollection::iterator ns_it;
    for (ns_it = mNamespaces->begin(); ns_it != mNamespaces->end(); ++ns_it) {
        PropertyCollection::iterator p_it;
        for (p_it = (*ns_it)->getProperties()->begin();
             p_it != (*ns_it)->getProperties()->end(); ++p_it) {
            for (int i = 0; i < (*p_it)->getNumElements(); i++) {
                char fqn[255];
                char tmp[8];
                sprintf(tmp, "_%d", i);
                snprintf(fqn, sizeof(fqn), "%s.%s%s",
                         (*ns_it)->getName(), (*p_it)->getName(),
                         ((*p_it)->getNumElements() > 1 ? tmp : ""));
                if (!strcasecmp(name, fqn)) {
                    pthread_mutex_unlock(&mLock);
                    return doSet((*p_it), i, value);
                }
            }
        }
    }

    LOGE("Property %s not found", name);
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return -1;
}

const char *PropertyManager::get(const char *name, char *buffer, size_t max) {
    pthread_mutex_lock(&mLock);
    PropertyNamespaceCollection::iterator ns_it;
    for (ns_it = mNamespaces->begin(); ns_it != mNamespaces->end(); ++ns_it) {
        PropertyCollection::iterator p_it;
        for (p_it = (*ns_it)->getProperties()->begin();
             p_it != (*ns_it)->getProperties()->end(); ++p_it) {

            for (int i = 0; i < (*p_it)->getNumElements(); i++) {
                char fqn[255];
                char tmp[8];
                sprintf(tmp, "_%d", i);
                snprintf(fqn, sizeof(fqn), "%s.%s%s",
                         (*ns_it)->getName(), (*p_it)->getName(),
                         ((*p_it)->getNumElements() > 1 ? tmp : ""));
                if (!strcasecmp(name, fqn)) {
                    pthread_mutex_unlock(&mLock);
                    if (doGet((*p_it), i, buffer, max))
                        return NULL;
                    return buffer;
                }
            }
        }
    }

    LOGE("Property %s not found", name);
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return NULL;
}

android::List<char *> *PropertyManager::createPropertyList(const char *prefix) {
    android::List<char *> *c = new android::List<char *>();

    pthread_mutex_lock(&mLock);
    PropertyNamespaceCollection::iterator ns_it;
    for (ns_it = mNamespaces->begin(); ns_it != mNamespaces->end(); ++ns_it) {
        PropertyCollection::iterator p_it;
        for (p_it = (*ns_it)->getProperties()->begin();
             p_it != (*ns_it)->getProperties()->end(); ++p_it) {
            for (int i = 0; i < (*p_it)->getNumElements(); i++) {
                char fqn[255];
                char tmp[8];
                sprintf(tmp, "_%d", i);
                snprintf(fqn, sizeof(fqn), "%s.%s%s",
                         (*ns_it)->getName(), (*p_it)->getName(),
                         ((*p_it)->getNumElements() > 1 ? tmp : ""));
                if (!prefix ||
                    (prefix && !strncasecmp(fqn, prefix, strlen(prefix)))) {
                    c->push_back(strdup(fqn));
                }
            }
        }
    }
    pthread_mutex_unlock(&mLock);
    return c;
}
