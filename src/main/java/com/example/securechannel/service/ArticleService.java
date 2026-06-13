package com.example.securechannel.service;

import com.example.securechannel.exception.BadRequestException;
import com.example.securechannel.model.Article;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Service;

@Service
public class ArticleService {

    private final AtomicLong idSequence = new AtomicLong(1);
    private final Map<Long, Article> articles = new ConcurrentHashMap<>();

    public Article create(String title, String description) {
        long id = idSequence.getAndIncrement();
        Article article = new Article(id, title, description);
        articles.put(id, article);
        return article;
    }

    public Article getById(long id) {
        Article article = articles.get(id);
        if (article == null) {
            throw new BadRequestException("Article not found");
        }
        return article;
    }

    public List<Article> getAll() {
        return articles.values().stream()
                .sorted(Comparator.comparingLong(Article::id))
                .toList();
    }
}

