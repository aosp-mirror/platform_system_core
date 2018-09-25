/*
 * Copyright (C) 2016 The Android Open Source Project
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

// Based on system/update_engine/payload_generator/tarjan.cc

#ifndef LIBMEMUNREACHABLE_TARJAN_H_
#define LIBMEMUNREACHABLE_TARJAN_H_

#include <assert.h>
#include <algorithm>

#include "Allocator.h"

namespace android {

template <class T>
class Node {
 public:
  allocator::set<Node<T>*> references_in;
  allocator::set<Node<T>*> references_out;
  size_t index;
  size_t lowlink;

  T* ptr;

  Node(T* ptr, Allocator<Node> allocator)
      : references_in(allocator), references_out(allocator), ptr(ptr){};
  Node(Node&& rhs) noexcept = default;
  void Edge(Node<T>* ref) {
    references_out.emplace(ref);
    ref->references_in.emplace(this);
  }
  template <class F>
  void Foreach(F&& f) {
    for (auto& node : references_out) {
      f(node->ptr);
    }
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Node<T>);
};

template <class T>
using Graph = allocator::vector<Node<T>*>;

template <class T>
using SCC = allocator::vector<Node<T>*>;

template <class T>
using SCCList = allocator::vector<SCC<T>>;

template <class T>
class TarjanAlgorithm {
 public:
  explicit TarjanAlgorithm(Allocator<void> allocator)
      : index_(0), stack_(allocator), components_(allocator) {}

  void Execute(Graph<T>& graph, SCCList<T>& out);

 private:
  static constexpr size_t UNDEFINED_INDEX = static_cast<size_t>(-1);
  void Tarjan(Node<T>* vertex, Graph<T>& graph);

  size_t index_;
  allocator::vector<Node<T>*> stack_;
  SCCList<T> components_;
};

template <class T>
void TarjanAlgorithm<T>::Execute(Graph<T>& graph, SCCList<T>& out) {
  stack_.clear();
  components_.clear();
  index_ = 0;
  for (auto& it : graph) {
    it->index = UNDEFINED_INDEX;
    it->lowlink = UNDEFINED_INDEX;
  }

  for (auto& it : graph) {
    if (it->index == UNDEFINED_INDEX) {
      Tarjan(it, graph);
    }
  }
  out.swap(components_);
}

template <class T>
void TarjanAlgorithm<T>::Tarjan(Node<T>* vertex, Graph<T>& graph) {
  assert(vertex->index == UNDEFINED_INDEX);
  vertex->index = index_;
  vertex->lowlink = index_;
  index_++;
  stack_.push_back(vertex);
  for (auto& it : vertex->references_out) {
    Node<T>* vertex_next = it;
    if (vertex_next->index == UNDEFINED_INDEX) {
      Tarjan(vertex_next, graph);
      vertex->lowlink = std::min(vertex->lowlink, vertex_next->lowlink);
    } else if (std::find(stack_.begin(), stack_.end(), vertex_next) != stack_.end()) {
      vertex->lowlink = std::min(vertex->lowlink, vertex_next->index);
    }
  }
  if (vertex->lowlink == vertex->index) {
    SCC<T> component{components_.get_allocator()};
    Node<T>* other_vertex;
    do {
      other_vertex = stack_.back();
      stack_.pop_back();
      component.push_back(other_vertex);
    } while (other_vertex != vertex && !stack_.empty());

    components_.emplace_back(component);
  }
}

template <class T>
void Tarjan(Graph<T>& graph, SCCList<T>& out) {
  TarjanAlgorithm<T> tarjan{graph.get_allocator()};
  tarjan.Execute(graph, out);
}

}  // namespace android

#endif  // LIBMEMUNREACHABLE_TARJAN_H_
